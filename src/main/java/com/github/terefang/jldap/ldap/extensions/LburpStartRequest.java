/* **************************************************************************
 * $OpenLDAP$
 *
 * Copyright (C) 1999, 2000, 2001 Novell, Inc. All Rights Reserved.
 *
 * THIS WORK IS SUBJECT TO U.S. AND INTERNATIONAL COPYRIGHT LAWS AND
 * TREATIES. USE, MODIFICATION, AND REDISTRIBUTION OF THIS WORK IS SUBJECT
 * TO VERSION 2.0.1 OF THE OPENLDAP PUBLIC LICENSE, A COPY OF WHICH IS
 * AVAILABLE AT HTTP://WWW.OPENLDAP.ORG/LICENSE.HTML OR IN THE FILE "LICENSE"
 * IN THE TOP-LEVEL DIRECTORY OF THE DISTRIBUTION. ANY USE OR EXPLOITATION
 * OF THIS WORK OTHER THAN AS AUTHORIZED IN VERSION 2.0.1 OF THE OPENLDAP
 * PUBLIC LICENSE, OR OTHER PRIOR WRITTEN CONSENT FROM NOVELL, COULD SUBJECT
 * THE PERPETRATOR TO CRIMINAL AND CIVIL LIABILITY.
 ******************************************************************************/
package com.github.terefang.jldap.ldap.extensions;

import com.github.terefang.jldap.ldap.*;
import com.github.terefang.jldap.ldap.asn1.*;
import com.github.terefang.jldap.ldap.resources.*;
import java.io.IOException;
import java.io.ByteArrayOutputStream;


public class LburpStartRequest extends LDAPExtendedOperation {

    static
    {
		/*
         * Register the extendedresponse class which is returned by the
		 * server in response to a LburpStartRequest
		 */
        try {
            LDAPExtendedResponse.register(
                  LburpConstants.LBURPStartReplResOID,
                  Class.forName(
                          "com.github.terefang.jldap.ldap.extensions.LburpStartResponse"));
        }catch (ClassNotFoundException e) {
            System.err.println("Could not register Extended Response -" +
                               " Class not found");
        }catch(Exception e){
           e.printStackTrace();
        }
        
    }

                                         
    public LburpStartRequest(String lburpProtocolOID)
                     throws LDAPException {

        super(LburpConstants.LBURPStartReplReqOID, null);

        try {

            if ( (lburpProtocolOID == null)  )
                throw new IllegalArgumentException(
                                         ExceptionMessages.PARAM_ERROR);

            ByteArrayOutputStream encodedData = new ByteArrayOutputStream();
            LBEREncoder encoder  = new LBEREncoder();

            ASN1Sequence asn1_lpSeq = new ASN1Sequence();
            ASN1OctetString asn1_lpOID = new ASN1OctetString(lburpProtocolOID);
            asn1_lpSeq.add(asn1_lpOID);

            asn1_lpSeq.encode(encoder, encodedData);
            setValue(encodedData.toByteArray());

        }catch(IOException ioe) {
         throw new LDAPException(ExceptionMessages.ENCODING_ERROR,
                                 LDAPException.ENCODING_ERROR,(String)null);
        }
    }

}
