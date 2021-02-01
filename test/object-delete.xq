xquery version "3.1";

(: Test object:delete :)

import module namespace aws_config = "http://history.state.gov/ns/xquery/aws_config" at "/db/apps/s3/modules/aws_config.xqm";
import module namespace object = "http://www.xquery.co.uk/modules/connectors/aws/s3/object" at "/db/apps/s3/modules/xaws/modules/uk/co/xquery/www/modules/connectors/aws-exist/s3/object.xq";
import module namespace hsg-config = "http://history.state.gov/ns/site/hsg/config" at '/db/apps/hsg-shell/modules/config.xqm';

let $aws-access-key := $aws_config:AWS-ACCESS-KEY
let $aws-secret := $aws_config:AWS-SECRET-KEY
let $bucket := $hsg-config:S3_BUCKET
let $key := "temp/test.txt"
let $content := "test"
return
    (
        object:write($aws-access-key, $aws-secret, $bucket, $key, $content),
        object:read($aws-access-key, $aws-secret, $bucket, $key),
        object:get-config-acl($aws-access-key, $aws-secret, $bucket, $key),
        object:delete($aws-access-key, $aws-secret, $bucket, $key)
    )
