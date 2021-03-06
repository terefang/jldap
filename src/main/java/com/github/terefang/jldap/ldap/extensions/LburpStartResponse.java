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
import com.github.terefang.jldap.ldap.rfc2251.*;
import java.io.IOException;

public class LburpStartResponse extends LDAPExtendedResponse {
    
    int tranSize;
                                    
    public LburpStartResponse(RfcLDAPMessage rfcMessage)
                throws IOException{

        super(rfcMessage);
        byte [] returnedValue = this.getValue();
        
        if (returnedValue == null)
                throw new IOException("No returned value");

            // Create a decoder object
        LBERDecoder decoder = new LBERDecoder();
        if (decoder == null)
                throw new IOException("Decoding error");
       
        ASN1Sequence returnedSequence = (ASN1Sequence)
                                            decoder.decode(returnedValue);
        if (returnedSequence == null)
                throw new IOException("Decoding error");

         
        tranSize = ((ASN1Integer)returnedSequence.get(0)).intValue();
    }
    
    public int getTranSize() 
    {
        return tranSize;
    }
}


