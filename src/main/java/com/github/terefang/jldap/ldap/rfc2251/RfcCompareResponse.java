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
package com.github.terefang.jldap.ldap.rfc2251;

import java.io.IOException;
import java.io.InputStream;
import com.github.terefang.jldap.ldap.*;
import com.github.terefang.jldap.ldap.asn1.*;

/**
 * Represents and LDAP Compare Response.
 *
 *<pre>
 *      CompareResponse ::= [APPLICATION 15] LDAPResult
 *</pre>
 */
public class RfcCompareResponse extends RfcLDAPResult {

    //*************************************************************************
    // Constructor for CompareResponse
    //*************************************************************************

    /**
     * The only time a client will create a CompareResponse is when it is
     * decoding it from an InputStream
     */
    public RfcCompareResponse(ASN1Decoder dec, InputStream in, int len)
        throws IOException
    {
        super(dec, in, len);
    }

    /**
     * Constructs an RfcCompareResponse from parameters.
     *
     * @param resultCode the result code of the operation
     *
     * @param matchedDN the matched DN returned from the server
     *
     * @param errorMessage the diagnostic message returned from the server
     *
     * @param referral the referral(s) returned by the server
     */
    public RfcCompareResponse(ASN1Enumerated resultCode, RfcLDAPDN matchedDN,
                        RfcLDAPString errorMessage, RfcReferral referral)
    {
        super(resultCode, matchedDN, errorMessage, referral);
        return;
    }
    
    //*************************************************************************
    // Accessors
    //*************************************************************************

    /**
     * Override getIdentifier to return an application-wide id.
     */
    public final ASN1Identifier getIdentifier()
    {
        return new ASN1Identifier(ASN1Identifier.APPLICATION, true,
                                   LDAPMessage.COMPARE_RESPONSE);
    }
}
