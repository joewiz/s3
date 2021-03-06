(:
 : Copyright 2010 XQuery.co.uk
 :
 : Licensed under the Apache License, Version 2.0 (the "License");
 : you may not use this file except in compliance with the License.
 : You may obtain a copy of the License at
 :
 : http://www.apache.org/licenses/LICENSE-2.0
 :
 : Unless required by applicable law or agreed to in writing, software
 : distributed under the License is distributed on an "AS IS" BASIS,
 : WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 : See the License for the specific language governing permissions and
 : limitations under the License.
:)

(:~
 : <p>
 : </p>
 :
 : @author Klaus Wichmann klaus [at] xquery [dot] co [dot] uk
 :)
module namespace factory = 'http://www.xquery.co.uk/modules/connectors/aws/s3/factory';

import module namespace http = "http://expath.org/ns/http-client";
import module namespace ser = "http://www.zorba-xquery.com/modules/serialize";
import module namespace hash = "http://www.zorba-xquery.com/modules/security/hash";
import module namespace base64 = "http://www.zorba-xquery.com/modules/base64";

import module namespace date = "http://www.zorba-xquery.com/modules/datetime";


(:~
 : Generate a s3:CreateBucketConfiguration to be added to a create-bucket request.
 :
 : @param $location the location where the bucket should be created
 : @return the s3:CreateBucketConfiguration element
:)
declare function factory:config-create-bucket-location($location as xs:string) as element() {

    <CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        <LocationConstraint>{$location}</LocationConstraint>
    </CreateBucketConfiguration>
};

(:~
 : Generate an AccessControlPolicy that can be added to an acl put request.
 :
 : @param $ownerid optional ID of the bucket owner
 : @param $owneremail optional email address of the bucket owner
 : @param $grants a sequence of grants (contains user/group identifier plus permission)
 : @return an AccessControlPolicy with an empty AccessControlList
:)
declare function factory:config-acl($ownerid as xs:string?,$owneremail as xs:string?,$grants as element(Grant)*) as element() {

    <AccessControlPolicy>
        {
            if(($ownerid,$owneremail))
            then
                <Owner>
                {
                    if($ownerid) then <ID>{$ownerid}</ID> else(),
                    if($owneremail) then <DisplayName>{$owneremail}</DisplayName> else ()
                }
                </Owner>
            else ()
        }
        <AccessControlList>{$grants}</AccessControlList>
    </AccessControlPolicy> 
};

(:~
 : Generate a Grant that can be inserted into an AccessControlList within an AccessControlPolicy to grant an 
 : access right to a specific grantee or user group.
 :
 : @param $granteeid Can be a unique AWS user id, an email address of an Amazon Customer, or a URI to identify a group of users.
 : @param $permission the permission to grant to a specific user or group of users
 : @return an AccessControlPolicy with an empty AccessControlList
:)
declare function factory:config-grant($granteeid as xs:string,$permission as xs:string) as element() {

    <Grant>
        {
        switch ($granteeid)
            case starts-with($granteeid,"http://") 
                return
                    <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group">
                        <URI>{$granteeid}</URI>
                    </Grantee> 
            case contains($granteeid,"@") 
                return
                    <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="AmazonCustomerByEmail">
                        <EmailAddress>{$granteeid}</EmailAddress>
                    </Grantee> 
            default 
                return
                    <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
                        <ID>{$granteeid}</ID>
                    </Grantee> 
        }        
        <Permission>{$permission}</Permission>
    </Grant>
};

(:~
 : Generate a s3:BucketLoggingStatus to be added to an enable-logging request.
 :
 : @param $logging-bucket the bucket where the logs are stored (optional)
 : @param $logging-prefix all logs for the logged bucket will start with this prefix (optional)
 : @return the s3:BucketLoggingStatus element
:)
declare function factory:config-enable-bucket-logging($logging-bucket as xs:string?, $logging-prefix as xs:string?) as element() {

    <BucketLoggingStatus xmlns="http://doc.s3.amazonaws.com/2006-03-01">
        <LoggingEnabled>
        {
            if ($logging-bucket) then <TargetBucket>{$logging-bucket}</TargetBucket> else (),
            if ($logging-prefix) then <TargetPrefix>{$logging-prefix}</TargetPrefix> else () 
        }
        </LoggingEnabled>
    </BucketLoggingStatus>
};

(:~
 : Generate a s3:BucketLoggingStatus to be added to an disable-logging request.
 :
 : @return the s3:BucketLoggingStatus element
:)
declare function factory:config-disable-bucket-logging() as element() {

    <BucketLoggingStatus xmlns="http://doc.s3.amazonaws.com/2006-03-01" />
};

(:~
 : Generate a NotificationConfiguration to be added to an enable-lost-object-notification request.
 :
 : @param $topic the topic through which the lost object notification will be send
 : @return the NotificationConfiguration element
:)
declare function factory:config-enable-lost-object-notification($topic as xs:string) as element() {

    <NotificationConfiguration>
        <TopicConfiguration>
            <Topic>{$topic}</Topic>
            <Event>s3:ReducedRedundancyLostObject</Event>
        </TopicConfiguration>
    </NotificationConfiguration>
};

(:~
 : Generate a NotificationConfiguration to be added to an disable-lost-object-notification request.
 :
 : @return the NotificationConfiguration element
:)
declare function factory:config-disable-lost-object-notification() as element() {

    <NotificationConfiguration />
};

(:~
 : Generate a RequestPaymentConfiguration to be added to an request-payment-configuration request.
 :
 : @param $payer the payer to be set to pay for request and transfer cost for a bucket
 : @return the s3:RequestPaymentConfiguration element
:)
declare function factory:config-request-payment($payer as xs:string) as element() {

    <RequestPaymentConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        <Payer>{$payer}</Payer>
    </RequestPaymentConfiguration>
};

(:~
 : Generate a VersioningConfiguration to enable versioning for a specific bucket
 :
 : @return the s3:VersioningConfiguration element
:)
declare function factory:config-enable-versioning() as element() {

    <VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        <Status>Enabled</Status>
    </VersioningConfiguration>
};

(:~
 : Generate a VersioningConfiguration to enable versioning for a specific bucket
 :
 : @param $mfa-delete true to enable mfa-delete for a bucket, false to disable mfa-delete
 : @return the s3:VersioningConfiguration element
:)
declare function factory:config-enable-versioning($mfa-delete as xs:boolean) as element() {

    <VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        <Status>Enabled</Status>
        <MfaDelete>{if ( $mfa-delete ) then "Enabled" else "Disabled" }</MfaDelete>
    </VersioningConfiguration>
};

(:~
 : Generate a VersioningConfiguration to disable versioning for a specific bucket
 :
 : @return the s3:VersioningConfiguration element
:)
declare function factory:config-disable-versioning() as element() {

    <VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        <Status>Suspended</Status>
    </VersioningConfiguration>
};

(:~
 : Generate a VersioningConfiguration to disable versioning for a specific bucket
 :
 : @param $mfa-delete true to enable mfa-delete for a bucket, false to disable mfa-delete
 : @return the s3:VersioningConfiguration element
:)
declare function factory:config-disable-versioning($mfa-delete as xs:boolean) as element() {

    <VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        <Status>Suspended</Status>
        <MfaDelete>{if ( $mfa-delete ) then "Enabled" else "Disabled" }</MfaDelete>
    </VersioningConfiguration>
};

