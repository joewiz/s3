xquery version "3.1";

(: store the contents of the FSI/OH S3 bucket behind "static.history.state.gov" into the /db/apps/s3/cache directory
 : 
 : instead of static keys from an IAM user, this uses Secure Token Service tokens, which means it can only be run on 
 : EC2 instances with instance profiles granting it this permission. it will not work on local development instances.
 :)

import module namespace aws-request = 'http://www.xquery.co.uk/modules/connectors/aws/helpers/request' at '/db/apps/s3/modules/xaws/modules/uk/co/xquery/www/modules/connectors/aws-exist/helpers/request.xq';
import module namespace hsg-config = "http://history.state.gov/ns/site/hsg/config" at '/db/apps/hsg-shell/modules/config.xqm';
import module namespace s3_request = 'http://www.xquery.co.uk/modules/connectors/aws/s3/request' at '/db/apps/s3/modules/xaws/modules/uk/co/xquery/www/modules/connectors/aws-exist/s3/request.xq';

declare namespace functx = "http://www.functx.com";
declare namespace http="http://expath.org/ns/http-client";
declare namespace s3="http://s3.amazonaws.com/doc/2006-03-01/";

declare variable $local:bucket := $hsg-config:S3_BUCKET;
declare variable $local:credentials-ttl-seconds := 1200; (: 20 minutes is long enough to list bucket contents :)

(: 
 : Use AWS Security Token Service to fetch and cache temporary credentials
 : @see https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html
 : @see https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html
:)
declare function local:get-credentials($ttl-seconds as xs:integer) {
    let $cached-credentials := cache:get("instance-profile", "credentials")
    return
        if (exists($cached-credentials)) then
            if (xs:dateTime($cached-credentials?Expiration) ge current-dateTime()) then
                (
                    cache:clear("instance-profile"),
                    local:get-credentials($ttl-seconds)
                )
            else
                $cached-credentials
        else
            let $get-token-url := "http://169.254.169.254/latest/api/token"
            let $get-token-request := 
                <http:request href="{$get-token-url}" method="PUT">
                    <http:header name="x-aws-ec2-metadata-token-ttl-seconds" value="{$ttl-seconds}"/>
                </http:request>
            let $token := hc:send-request($get-token-request)[2]
            let $get-security-credentials-url := "http://169.254.169.254/latest/meta-data/iam/security-credentials"
            let $get-security-credentials-request := 
                <http:request href="{$get-security-credentials-url}" method="GET">
                    <http:header name="X-aws-ec2-metadata-token" value="{$token}"/>
                </http:request>
            let $security-credentials := hc:send-request($get-security-credentials-request)[2]
            let $get-temporary-credential-url := "http://169.254.169.254/latest/meta-data/iam/security-credentials/" || $security-credentials
            let $temporary-credentials-request := 
                <http:request href="{$get-temporary-credential-url}" method="GET">
                    <http:header name="X-aws-ec2-metadata-token" value="{$token}"/>
                </http:request>
            let $credentials := hc:send-request($temporary-credentials-request)[2] => parse-json()
            let $expire-ms := (min(($ttl-seconds, 5)) - 5) * 1000 (: expire cache 5 seconds before credentials actually expire :)
            let $cache-create := 
                cache:create(
                    "instance-profile", 
                    map {
                        "expireAfterAccess": $expire-ms, 
                        "expireAfterWrite": $expire-ms, 
                        (: expireAfterWrite to be released with eXist 6.2.1 - see https://github.com/eXist-db/exist/pull/4975
                         : TODO switch from expireAfterAccess to expireAfterWrite when we adopt this release :)
                        "permissions": 
                            map { 
                                "put-group": "dba", 
                                "get-group": "dba", 
                                "remove-group": "dba", 
                                "clear-group": "dba"
                            }
                    }
                ) 
            let $cache-put := cache:put("instance-profile", "credentials", $credentials) 
            return 
                $credentials
};

declare function functx:substring-after-last-match 
  ( $arg as xs:string? ,
    $regex as xs:string )  as xs:string {
       
   replace($arg,concat('^.*',$regex),'')
 } ;

(: adds a security token parameter to the bucket:list() function from /db/apps/s3/modules/xaws/modules/uk/co/xquery/www/modules/connectors/aws-exist/s3/bucket.xq :)
declare function local:bucket-list-with-security-token(
    $aws-access-key as xs:string, 
    $aws-secret as xs:string,
    $security-token as xs:string,
    $bucket as xs:string,
    $delimiter as xs:string?,
    $marker as xs:string?,
    $max-keys as xs:string?,
    $prefix as xs:string?
) as item()* {    
    let $href as xs:string := concat("https://s3.amazonaws.com/", $bucket, "/")
    let $parameters := 
        (
            <parameter name="X-Amz-Security-Token" value="{$security-token}" />,
            if (exists($delimiter)) then <parameter name="delimiter" value="{$delimiter}" /> else (),
            if (exists($marker)) then <parameter name="marker" value="{$marker}" /> else (),
            if (exists($max-keys)) then <parameter name="max-keys" value="{$max-keys}" /> else (),
            if (exists($prefix)) then <parameter name="prefix" value="{$prefix}" /> else ()
        )
    let $request := aws-request:create("GET", $href, $parameters)
    let $sign := aws-request:sign_v4($request, $bucket, '', $aws-access-key, $aws-secret)
    return 
        s3_request:send($sign)
};

declare function local:contents-to-resources($contents) {
    for $item in $contents
    let $key := data($item/s3:Key)
    let $filename := functx:substring-after-last-match($key, '/')
    let $size := data($item/s3:Size)
    let $last-modified := data($item/s3:LastModified)
    return
        <resource>
            <filename>{$filename}</filename>
            <s3-key>{$key}</s3-key>
            <size>{$size}</size>
            <last-modified>{$last-modified}</last-modified>
        </resource>
};

declare function local:get-child-resources($marker, $prefix, $content-cache) {
    let $credentials := local:get-credentials($local:credentials-ttl-seconds)
    let $list := local:bucket-list-with-security-token($credentials?AccessKeyId, $credentials?SecretAccessKey, $credentials?Token, $local:bucket, '/', $marker, '', $prefix)[2]
    let $contents := $list/s3:ListBucketResult/s3:Contents[s3:Key ne $prefix]
    let $consolidated-results := ($content-cache, $contents)
    return
        if ($list/s3:ListBucketResult/s3:IsTruncated eq 'true') then
            let $next-marker := $list/s3:ListBucketResult/s3:NextMarker
            return
                local:get-child-resources($next-marker, $prefix, $consolidated-results)
        else
            local:contents-to-resources($consolidated-results)
};

declare function local:get-child-resources($prefix) {
    local:get-child-resources('', $prefix, ())
};

declare function local:get-child-collections($prefix) {
    let $credentials := local:get-credentials($local:credentials-ttl-seconds)
    let $list := local:bucket-list-with-security-token($credentials?AccessKeyId, $credentials?SecretAccessKey, $credentials?Token, $local:bucket, '/', '', '', $prefix)[2]
    let $common-prefixes := $list/s3:ListBucketResult/s3:CommonPrefixes/s3:Prefix
    for $common-prefix in $common-prefixes
    let $collection := substring-before(substring-after($common-prefix, $prefix), '/')
    return 
        <collection>{xmldb:encode($collection)}</collection>
};

declare function local:crawl-directory-tree($prefix, $db-collection) {
    (
    let $child-resources := <resources prefix="{$prefix}">{local:get-child-resources($prefix)}</resources>
    let $store := xmldb:store($db-collection, 'resources.xml', $child-resources)
    return 
        <result>Resources in {$prefix} stored in {$db-collection}</result>
    ,
    for $collection in local:get-child-collections($prefix)
    let $new-collection := xmldb:create-collection($db-collection, $collection)
    let $new-prefix := concat($prefix, $collection, '/')
    return 
        (
        <result>Created new collection {$new-collection}, crawling {$new-prefix}</result>
        ,
        local:crawl-directory-tree($new-prefix, $new-collection)
        )
    )
};

declare function local:store-bucket-tree($bucket, $db-collection) {
    let $new-collection := xmldb:create-collection($db-collection, $bucket)
    let $crawl := local:crawl-directory-tree('', $new-collection)
    return
        <results>
            {$crawl}
            <result>Completed crawl of {$bucket}.  Directory tree stored in {$new-collection}.</result>
        </results>
};

declare function local:store-directory-tree($prefix, $db-collection) {
    let $new-collection := xmldb:create-collection($db-collection, tokenize($prefix, '/')[position() = last() - 1])
    let $crawl := local:crawl-directory-tree($prefix, $new-collection)
    return
        <results>
            {$crawl}
            <result>Completed crawl of {$prefix}.  Directory tree stored in {$new-collection}.</result>
        </results>
};

(: create s3-resources directory if needed :)
if (not(xmldb:collection-available('/db/apps/s3/cache'))) then 
    xmldb:create-collection('/db/apps/s3', 'cache')
else
    ()
,
(: Cache information about all resources in the static.history.state.gov bucket into the /db/apps/s3/cache collection :)
(: 
:)
local:store-bucket-tree($local:bucket, '/db/apps/s3/cache'),

(: To cache information about the resources in just one directory (frus), comment out the previous expresison and uncomment one of the following. 
 : Note: the trailing slash in the 1st argument (i.e., in "frus/") is necessary for S3 directory names. :)
(: 
local:store-directory-tree("about/", '/db/apps/s3/cache/' || $local:bucket),
local:store-directory-tree("frus/frus1981-88v04/", '/db/apps/s3/cache/' || $local:bucket || '/frus'),
:)

<ok/>
