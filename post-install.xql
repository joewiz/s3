xquery version "3.0";

declare namespace repo="http://exist-db.org/xquery/repo";

(: The following external variables are set by the repo:deploy function :)

(: file path pointing to the exist installation directory :)
declare variable $home external;
(: path to the directory containing the unpacked .xar package :)
declare variable $dir external;
(: the target collection into which the app is deployed :)
declare variable $target external;

(:
 : Module "aws_config_tmpl.xqm", which is the template file for module "aws_config.xqm"
 : contains sensitive information, therefore we removed guest access to this file.
 :)
sm:chmod(xs:anyURI($target || "/modules/aws_config_tmpl.xqm"), "rwxrwx---")
