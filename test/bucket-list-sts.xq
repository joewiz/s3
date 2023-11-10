xquery version "3.1";

(: list the contents of an S3 bucket, using STS tokens
 :
 : instead of static keys from an IAM user, this uses Secure Token Service tokens, which means it can only be run on 
 : EC2 instances with instance profiles granting it this permission. it will not work on local development instances.
 :)

import module namespace aws-request = 'http://www.xquery.co.uk/modules/connectors/aws/helpers/request' at '/db/apps/s3/modules/xaws/modules/uk/co/xquery/www/modules/connectors/aws-exist/helpers/request.xq';
import module namespace hsg-config = "http://history.state.gov/ns/site/hsg/config" at '/db/apps/hsg-shell/modules/config.xqm';
import module namespace s3_request = 'http://www.xquery.co.uk/modules/connectors/aws/s3/request' at '/db/apps/s3/modules/xaws/modules/uk/co/xquery/www/modules/connectors/aws-exist/s3/request.xq';

declare namespace http="http://expath.org/ns/http-client";
declare namespace s3="http://s3.amazonaws.com/doc/2006-03-01/";

declare variable $local:bucket := $hsg-config:S3_BUCKET;

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


(: 
 : @see https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html
 : curl -ki -X PUT http://169.254.169.254/latest/api/token -H 'x-aws-ec2-metadata-token-ttl-seconds: 21600'
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

let $credentials := local:get-credentials(60)
let $aws-access-key := $credentials?AccessKeyId
let $aws-secret-key := $credentials?SecretAccessKey
let $security-token := $credentials?Token
return
    local:bucket-list-with-security-token($aws-access-key, $aws-secret-key, $security-token, $local:bucket, '/', '', '', '')
