xquery version "3.1";

(: Test bucket:list#7 :)

import module namespace aws_config = "http://history.state.gov/ns/xquery/aws_config" at "/db/apps/s3/modules/aws_config.xqm";
import module namespace bucket = "http://www.xquery.co.uk/modules/connectors/aws/s3/bucket" at "/db/apps/s3/modules/xaws/modules/uk/co/xquery/www/modules/connectors/aws-exist/s3/bucket.xq";
import module namespace hsg-config = "http://history.state.gov/ns/site/hsg/config" at '/db/apps/hsg-shell/modules/config.xqm';

let $aws-access-key := $aws_config:AWS-ACCESS-KEY
let $aws-secret := $aws_config:AWS-SECRET-KEY
let $bucket := $hsg-config:S3_BUCKET
let $delimiter := "/"
let $marker := ""
let $max-keys := 10
let $prefix := 
(:
    ""
    "buildings"
:)
    "buildings/"
return
    bucket:list($aws-access-key, $aws-secret, $bucket, $delimiter, $marker, $max-keys, $prefix)
