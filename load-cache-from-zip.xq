xquery version "3.0";

import module namespace unzip = "http://joewiz.org/ns/xquery/unzip" at "https://raw.githubusercontent.com/joewiz/unzip/master/unzip/unzip.xql";

import module namespace http="http://expath.org/ns/http-client";
import module namespace util="http://exist-db.org/xquery/util";
import module namespace xmldb="http://exist-db.org/xquery/xmldb";
import module namespace hsg-config = "http://history.state.gov/ns/site/hsg/config" at '/db/apps/hsg-shell/modules/config.xqm';

(: the following module was copied from https://gist.github.com/joewiz/5938909 :)

(: downloads a file from a remote HTTP server at $file-url and save it to an eXist-db $collection.
 : we try hard to recognize XML files and save them with the correct mimetype so that eXist-db can 
 : efficiently index and query the files; if it doesn't appear to be XML, though, we just trust 
 : the response headers :)
declare function local:http-download($file-url as xs:string, $collection as xs:string) as item()* {
    let $request := <http:request href="{$file-url}" method="GET" http-version="1.1"/>
    let $response := http:send-request($request)
    let $head := $response[1]
    
    (: These sample responses from EXPath HTTP client reveals where the response code, media-type, and filename can be found: 
    
        <http:response xmlns:http="http://expath.org/ns/http-client" status="200"  message="OK">
            <http:header name="connection"  value="close"/>
            <http:header name="transfer-encoding"  value="chunked"/>
            <http:header name="content-type"  value="application/zip"/>
            <http:header name="content-disposition"  value="attachment; filename=xqjson-master.zip"/>
            <http:header name="date"  value="Sat, 06 Jul 2013 05:59:04 GMT"/>
            <http:body media-type="application/zip"/>
        </http:response>
        
        <http:response xmlns:http="http://expath.org/ns/http-client" status="200"  message="OK">
            <http:header name="date"  value="Sat, 06 Jul 2013 06:26:34 GMT"/>
            <http:header name="server"  value="GitHub.com"/>
            <http:header name="content-type"  value="text/plain; charset=utf-8"/>
            <http:header name="status"  value="200 OK"/>
            <http:header name="content-disposition"  value="inline"/>
            <http:header name="content-transfer-encoding"  value="binary"/>
            <http:header name="etag"  value=""a6782b6125583f16632fa103a828fdd6""/>
            <http:header name="vary"  value="Accept-Encoding"/>
            <http:header name="cache-control"  value="private"/>
            <http:header name="keep-alive"  value="timeout=10, max=50"/>
            <http:header name="connection"  value="Keep-Alive"/>
            <http:body media-type="text/plain"/>
        </http:response>
    :)
    
    return
        (: check to ensure the remote server indicates success :)
        if ($head/@status = '200') then
            (: try to get the filename from the content-disposition header, otherwise construct from the $file-url :)
            let $filename := 
                if (contains($head/http:header[@name='content-disposition']/@value, 'filename=')) then 
                    $head/http:header[@name='content-disposition']/@value/substring-after(., 'filename=')
                else 
                    (: use whatever comes after the final / as the file name:)
                    replace($file-url, '^.*/([^/]*)$', '$1')
            (: override the stated media type if the file is known to be .xml :)
            let $media-type := $head/http:body/@media-type
            let $mime-type := 
                if (ends-with($file-url, '.xml') and $media-type = 'text/plain') then
                    'application/xml'
                else 
                    $media-type
            (: if the file is XML and the payload is binary, we need convert the binary to string :)
            let $content-transfer-encoding := $head/http:body[@name = 'content-transfer-encoding']/@value
            let $body := $response[2]
            let $file := 
                if (ends-with($file-url, '.xml') and $content-transfer-encoding = 'binary') then 
                    util:binary-to-string($body) 
                else 
                    $body
            return
                xmldb:store($collection, $filename, $file, $mime-type)
        else
            <error><message>Oops, something went wrong:</message>{$head}</error>
};

let $url := $hsg-config:S3_URL || '/temp/static.history.state.gov-ebooks-s3-cache.zip'
return
    try {
        let $collection := xmldb:create-collection('/db', 'hsg-temp')
        let $store := local:http-download($url, $collection)
        let $unzip := unzip:unzip($collection || '/static.history.state.gov-ebooks-s3-cache.zip', '/db/apps/s3/cache')
        let $cleanup := xmldb:remove($collection)
        return 
            <result>Stored cache files in s3 app</result>
    } catch * { 
        <error>
            {
                string-join(
                    ($err:code cast as xs:string, $err:description, $err:value, concat("Module: ", $err:module, " (line ", $err:line-number, ", column ", $err:column-number, ")")),
                    '. '
                )
            }
        </error>
    }
