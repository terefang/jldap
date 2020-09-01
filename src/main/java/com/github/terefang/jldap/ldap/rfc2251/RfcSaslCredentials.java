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

import com.github.terefang.jldap.ldap.asn1.*;

/**
 * Represents LDAP Sasl Credentials.
 *
 *<pre>
 *       SaslCredentials ::= SEQUENCE {
 *               mechanism               LDAPString,
 *               credentials             OCTET STRING OPTIONAL }
 *</pre>
 */
public class RfcSaslCredentials extends ASN1Sequence {

    //*************************************************************************
    // Constructors for SaslCredentials
    //*************************************************************************

    /**
     *
     */
    public RfcSaslCredentials(RfcLDAPString mechanism)
    {
        this(mechanism, null);
    }

    /**
     *
     */
    public RfcSaslCredentials(RfcLDAPString mechanism, ASN1OctetString credentials)
    {
        super(2);
        add(mechanism);
        if(credentials != null)
            add(credentials);
    }
}
