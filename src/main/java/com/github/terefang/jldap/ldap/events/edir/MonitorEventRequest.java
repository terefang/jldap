/* **************************************************************************
 * $OpenLDAP$
 *
 * Copyright (C) 1999-2002 Novell, Inc. All Rights Reserved.
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
package com.github.terefang.jldap.ldap.events.edir;

import com.github.terefang.jldap.ldap.LDAPException;
import com.github.terefang.jldap.ldap.LDAPExtendedOperation;
import com.github.terefang.jldap.ldap.LDAPExtendedResponse;
import com.github.terefang.jldap.ldap.LDAPIntermediateResponse;
import com.github.terefang.jldap.ldap.asn1.ASN1Enumerated;
import com.github.terefang.jldap.ldap.asn1.ASN1Integer;
import com.github.terefang.jldap.ldap.asn1.ASN1Sequence;
import com.github.terefang.jldap.ldap.asn1.ASN1Set;
import com.github.terefang.jldap.ldap.asn1.LBEREncoder;
import com.github.terefang.jldap.ldap.resources.ExceptionMessages;

import java.io.ByteArrayOutputStream;
import java.io.IOException;



/**
 * This class is used for registering for Edirectory events.
 * This request encodes an eventType and eventStatus, which
 * are send to the Edirectory Server. The class extracts the
 * above value from EdirEventSpecifier class.
 *
 * <p>
 * The MonitorEventRequest uses the following OID:<br>
 * &nbsp;&nbsp;&nbsp;2.16.840.1.113719.1.27.100.79
 * </p>
 *
 * <p>
 * The responseValue has the following format:<br>
 * requestValue ::= <br>
 * &nbsp;&nbsp;SEQUENCE {<br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;eventCount  INTEGER,<br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;events      SET OF {eventSpecifier },<br>
 * &nbsp;&nbsp;}<br>
 * eventSpecifier ::= <br>
 * &nbsp;&nbsp;SEQUENCE {<br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;eventType    INTEGER,<br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;eventStatus  ENUMERATED<br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; {<br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;AllEvents (0),<br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;SuccessfulEvents (1),<br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; FailedEvents (2) <br>
 * &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; }<br>
 * &nbsp;&nbsp;}<br>
 * </p>
 *
 * @see EdirEventSpecifier
 */
public class MonitorEventRequest extends LDAPExtendedOperation {
    static {
        /*
        * Register the extendedresponse class which is returned by the
        * server in response to a MonitorEventRequest
        */
        try {
            LDAPExtendedResponse.register(
                EdirEventConstant.NLDAP_MONITOR_EVENTS_RESPONSE,
                Class.forName(
                        "com.github.terefang.jldap.ldap.events.edir.MonitorEventResponse"
                )
            );

            ///CLOVER:OFF
        } catch (ClassNotFoundException e) {
            System.err.println(
                "Could not register Extended Response -"
                + " Class not found"
            );
        } catch (Exception e) {
            e.printStackTrace();

            ///CLOVER:ON
        }

        //Also try to register EdirEventIntermediateResponse
        try {
            LDAPIntermediateResponse.register(
                EdirEventConstant.NLDAP_EVENT_NOTIFICATION,
                Class.forName(
                    EdirEventIntermediateResponse.class.getName()
                )
            );

            ///CLOVER:OFF
        } catch (ClassNotFoundException e) {
            System.err.println(
                "Could not register LDAP Intermediate Response -"
                + " Class not found"
            );
        } catch (Exception e) {
            e.printStackTrace();

            ///CLOVER:ON
        }
    }

    /**
     * Default Constructor for the Monitor Event Request Used to Send a
     * Monitor Event Request to LDAPServer.
     *
     * @param specifiers The list of EdirEventSpecifiers to send to
     *        server.
     *
     * @throws LDAPException When the data encoding fails.
     */
    public MonitorEventRequest(final EdirEventSpecifier[] specifiers)
        throws LDAPException {
        super(EdirEventConstant.NLDAP_MONITOR_EVENTS_REQUEST, null);

        if ((specifiers == null)) {
            throw new IllegalArgumentException(
                ExceptionMessages.PARAM_ERROR
            );
        }

        ByteArrayOutputStream encodedData = new ByteArrayOutputStream();
        LBEREncoder encoder = new LBEREncoder();

        ASN1Sequence asnsequence = new ASN1Sequence();

        try {
            asnsequence.add(new ASN1Integer(specifiers.length));

            ASN1Set asnset = new ASN1Set();

            for (int i = 0; i < specifiers.length; i++) {
                ASN1Sequence specifiersequence = new ASN1Sequence();
                specifiersequence.add(
                    new ASN1Integer(specifiers[i].getEventclassification())
                );
                specifiersequence.add(
                    new ASN1Enumerated(specifiers[i].getEventtype())
                );

                asnset.add(specifiersequence);
            }

            asnsequence.add(asnset);

            asnsequence.encode(encoder, encodedData);
        } catch (IOException e) {
            throw new LDAPException(
                ExceptionMessages.ENCODING_ERROR,
                LDAPException.ENCODING_ERROR, (String) null
            );
        }

        setValue(encodedData.toByteArray());
    }
}
