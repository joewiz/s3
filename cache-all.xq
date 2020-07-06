xquery version "1.0";

(: store the contents of the PA/HO s3 bucket "static.history.state.gov" into the /db/history/data/s3-resources directory :)

import module namespace aws_config = "http://history.state.gov/ns/xquery/aws_config" at 'modules/aws_config.xqm';
import module namespace bucket = 'http://www.xquery.co.uk/modules/connectors/aws/s3/bucket' at 'modules/xaws/modules/uk/co/xquery/www/modules/connectors/aws-exist/s3/bucket.xq';

declare namespace httpclient="http://exist-db.org/xquery/httpclient";
declare namespace s3="http://s3.amazonaws.com/doc/2006-03-01/";
declare namespace functx = "http://www.functx.com"; 

declare variable $local:bucket := 'static.history.state.gov';

declare function functx:substring-after-last-match 
  ( $arg as xs:string? ,
    $regex as xs:string )  as xs:string {
       
   replace($arg,concat('^.*',$regex),'')
 } ;

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
    let $list := bucket:list($aws_config:AWS-ACCESS-KEY, $aws_config:AWS-SECRET-KEY, $local:bucket, '/', $marker, '', $prefix)[2]
    let $contents := $list/s3:ListBucketResult/s3:Contents[s3:Key ne $prefix]
    let $consolidated-results := ($content-cache, $contents)
    return
        if ($list/httpclient:body/s3:ListBucketResult/s3:IsTruncated eq 'true') then
            let $next-marker := $list/httpclient:body/s3:ListBucketResult/s3:NextMarker
            return
                local:get-child-resources($next-marker, $prefix, $consolidated-results)
        else
            local:contents-to-resources($consolidated-results)
};

declare function local:get-child-resources($prefix) {
    local:get-child-resources('', $prefix, ())
};

declare function local:get-child-collections($prefix) {
    let $list := bucket:list($aws_config:AWS-ACCESS-KEY, $aws_config:AWS-SECRET-KEY, $local:bucket, '/', '', '', $prefix)[2]
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
        <result>resources in {$prefix} stored in {$db-collection}</result>
    ,
    for $collection in local:get-child-collections($prefix)
    let $new-collection := xmldb:create-collection($db-collection, $collection)
    let $new-prefix := concat($prefix, $collection, '/')
    return 
        (
        <result>created new collection {$new-collection}, crawling {$new-prefix}</result>
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
local:store-bucket-tree($local:bucket, '/db/apps/s3/cache')
,

(: To cache information about the resources in just one directory (frus), comment out the previous expresison and uncomment the following one. 
 : Note: the trailing slash ("frus/") is necessary for directory names. :)
(: 
local:store-directory-tree("frus/", '/db/apps/s3/cache/static.history.state.gov')
:)

<ok/>
