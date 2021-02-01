xquery version "3.1";

(: Test object:write :)

import module namespace aws_config = "http://history.state.gov/ns/xquery/aws_config" at "/db/apps/s3/modules/aws_config.xqm";
import module namespace object = "http://www.xquery.co.uk/modules/connectors/aws/s3/object" at "/db/apps/s3/modules/xaws/modules/uk/co/xquery/www/modules/connectors/aws-exist/s3/object.xq";
import module namespace const = "http://www.xquery.co.uk/modules/connectors/aws/s3/constants" at "/db/apps/s3/modules/xaws/modules/uk/co/xquery/www/modules/connectors/aws-exist/s3/constants.xq";
import module namespace hsg-config = "http://history.state.gov/ns/site/hsg/config" at '/db/apps/hsg-shell/modules/config.xqm';

let $aws-access-key := $aws_config:AWS-ACCESS-KEY
let $aws-secret := $aws_config:AWS-SECRET-KEY
let $bucket := $hsg-config:S3_BUCKET
return
    (
        object:write($aws-access-key, $aws-secret, $bucket, "temp/test.txt", "test"),
        object:write($aws-access-key, $aws-secret, $bucket, "temp/test.xml", "<x>test</x>"),
        object:write($aws-access-key, $aws-secret, $bucket, "temp/test.gif", xs:base64Binary("R0lGODlhEAAOALMAAOazToeHh0tLS/7LZv/0jvb29t/f3//Ub//ge8WSLf/rhf/3kdbW1mxsbP//mf///yH5BAAAAAAALAAAAAAQAA4AAARe8L1Ekyky67QZ1hLnjM5UUde0ECwLJoExKcppV0aCcGCmTIHEIUEqjgaORCMxIC6e0CcguWw6aFjsVMkkIr7g77ZKPJjPZqIyd7sJAgVGoEGv2xsBxqNgYPj/gAwXEQA7"))
    )
