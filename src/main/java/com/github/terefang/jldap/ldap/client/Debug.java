// $OpenLDAP$
// **
// ** NOTICE: Do NOT edit file Debug.java, the real file is Debug.template
// **
/******************************************************************************
 * Copyright (C) 1999 - 2002 Novell, Inc. All Rights Reserved.
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

package com.github.terefang.jldap.ldap.client;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.PrintStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Properties;
import java.util.Date;
import java.util.StringTokenizer;
import java.text.SimpleDateFormat;

/**
 * The <code>Debug</code> class contains several useful debugging class (static)
 * methods. It cannot be instantiated.
 * Some methods give useful information, such as amount of memory used,
 * enabling instruction tracing, displaying object hierarchy, and dumping
 * the contents of a raw <code>byte</code> buffer.
 * <p>
 * <p>
 * Another type of debug supports two kinds of methods; those that inform
 * whether a debug option is set or not; and those that output the specified
 * string to the <code>debugOut</code> stream when the associated debug value
 * is set.
 * <p>
 * The Debug class checks in the object returned by <code>System.getProperties</code>
 * for the name <b>ldap.debug</b> which has the following valid values:
 * <ul>
 * <li><b><code>VMtraceInstructions</code></b> - Enables instruction trace</u>
 * <li><b><code>VMtraceMethodCalls</code></b> - Enables method call trace</u>
 * <li><b><code>trace</code></b> - Displays a string if the named property is set</u>
 * <li><b><code>dumpBuffer</code></b> - Displays raw buffer dumps</u>
 * <li><b><code>dumpObject</code></b> - Displays information about an object.
 * The following property values can limit the information displayed. If
 * dumpObject is selected, all those listed below are also selected</u>
 * <li><b><code>dumpObjectHierarchy</code></b> - Displays object hierarchy</u>
 * <li><b><code>dumpObjectConstructors</code></b> - Displays object constructors</u>
 * <li><b><code>dumpObjectFields</code></b> - Displays object fields</u>
 * <li><b><code>dumpObjectMethods</code></b> - Displays object methods</u>
 * </ul>
 * <p>
 * If multiple values are desired, they are separated by semicolon's, i.e.
 * <ul>
 * <code>java -Dldap.debug=serverprogress;echodebug TServer -tree junk</code>
 * </ul>
 * The values are case insensitive.  Invalid values are ignored.
 * <p>
 * The <code>ldap_debug</code> variable allows debug code to be excluded
 * from a compile by codeing something like the following:
 * <ul>
 * <li><code>if( Debug.LDAP_DEBUG) trace(trace.referrals, "Entering referral code");</code>
 * </ul>
 *
 * @author Steven F. Sonntag
 * @version $OpenLDAP$
 */

public abstract class Debug {

    static SimpleDateFormat formatter = new SimpleDateFormat ("HH:mm:ss.SSS");
    /**
     * The value for this variable is set during compile time
     *  TRUE = Debug build, FALSE = Release build
     */
    public static final boolean LDAP_DEBUG = true;

    /**
     * The string value used to enable all debug tracing.
     */
    public static final String all = "TraceAll";
    /**
     * The string value used to enable debug tracing of raw input.
     */
    public static final String rawInput = "RawInput";
    /**
     * The string value used to enable debug tracing of Raw Output.
     */
    public static final String rawOutput = "RawOutput";
    /**
     * The string value used to enable debug tracing of referral processing.
     */
    public static final String referrals = "Referrals";
    /**
     * The string value used to enable debug tracing of message processing
     */
    public static final String messages = "Messages";
    /**
     * The string value used to enable debug tracing of API Requests
     */
    public static final String apiRequests = "APIRequests";
    /**
     * The string value used to enable debug tracing of the bind semaphore
     */
    public static final String bindSemaphore = "BindSemaphore";
        /**
     * The string value used to enable debug tracing of Controls
     */
    public static final String controls = "Controls";
    /**
     * The string value used to enable debug tracing of ASN1 encode/decode
     */
    public static final String asn1 = "ASN1";
    /**
     * The string value used to enable debug tracing of BER Encoding.
     */
    public static final String encoding = "Encoding";
    /**
     * The string value used to enable debug tracing of Ber Decoding.
     */
    public static final String decoding = "Decoding";
    /**
     * The string value used to enable debug tracing of LDAP Connections.
     */
    public static final String connections = "Connections";
    /**
     * The string value used to enable debug tracing of Sasl Bind processing.
     */
    public static final String saslBind = "SaslBind";
    /**
     * The string value used to enable display of TLS calls and info for
     * startTLS and stopTLS.
     */
    public static final String TLS = "TraceTLS";
    /**
     * The string value used to enable debug tracing of URL parsing.
     */
    public static final String urlParse = "UrlParse";
    /**
     * The string value used to enable debug display of buffer dumps.
     */
    public static final String buffer = "DumpBuffer";
    /**
     * The string value used to enable debug display of object dumps.
     * Displays hierarchy, constructors, fields, and methods.
     */
    public static final String objects = "DumpObject";
    /**
     * The string value used to enable debug display of object hierarchy dumps.
     */
    public static final String objectHierarchy = "DumpObjectHierarchy";
    /**
     * The string value used to enable debug display of object constructor dumps.
     */
    public static final String objectConstructors = "DumpObjectConstructors";
    /**
     * The string value used to enable debug display of object field dumps.
     */
    public static final String objectFields = "DumpObjectFields";
    /**
     * The string value used to enable debug display of object methods dumps.
     */
    public static final String objectMethods = "DumpObjectMethods";
    /**
     * The string value used to enable VM instruction trace.
     */
    public static final String traceInstructions = "VMTraceInstructions";
    /**
     * The string value used to enable display VM method calls.
     */
    public static final String traceMethodCalls = "VMTraceMethodCalls";
	/**
	* The string value used to enable display of Events Calls.
	*/
    public static final String EventsCalls = "EventsTrace";

    
    /*
     * Write the debug text to this PrintStream
     */
    private static PrintStream debugOut = System.err;

    private static boolean dumpBuffer = false;
    private static boolean dumpObject = false;
    private static boolean dumpObjectHierarchy = false;
    private static boolean dumpObjectConstructors = false;
    private static boolean dumpObjectFields = false;
    private static boolean dumpObjectMethods = false;
    private static boolean VMtraceInstructions = false;
    private static boolean VMtraceMethodCalls = false;
    private static boolean traceControls = false;
    private static boolean traceRawInput = false;
    private static boolean traceRawOutput = false;
    private static boolean traceASN1 = false;
    private static boolean traceEncoding = false;
    private static boolean traceDecoding = false;
    private static boolean traceReferrals = false;
    private static boolean traceMessages = false;
    private static boolean traceBindSemaphore = false;
    private static boolean traceAPIRequests = false;
    private static boolean traceUrlParse = false;
    private static boolean traceConnections = false;
    private static boolean traceTLS = false;
    private static boolean traceSaslBind = false;
    private static boolean traceevents = false;
    private static Properties objprop = new Properties();
    private static Runtime run = Runtime.getRuntime(); // for trace, etc.


    private Debug()
    {
        return;
    }

    /*
     * toggle the state of a boolean variable
     */
    static private final boolean toggle( boolean b) {
        if( b )
            b = false;
        else
            b = true;
        return b;
    }

    /**
    * The constructor reads the system properties and set booleans that
    * control the various debug options.
    */
    static
    {
        if( LDAP_DEBUG) {
            Properties prop = System.getProperties();
            String sep = prop.getProperty("path.separator",";");
            StringTokenizer st =
                    new StringTokenizer(prop.getProperty("ldap.debug",""), sep);
            while( st.hasMoreTokens()) {
                String tn = new String( st.nextToken());
                /*
                 * Properties that turn on VM trace methods
                 */
                if( tn.equalsIgnoreCase("VMTraceInstructions")) {
                    VMtraceInstructions = true;
                    VMtraceInstructions(true);
                } else if( tn.equalsIgnoreCase("VMTraceMethodCalls")) {
                    VMtraceMethodCalls = true;
                    VMtraceMethodCalls(true);
                /*
                 * Properties that turn on object dump methods
                 */
                } else if( tn.equalsIgnoreCase(buffer)) {
                    dumpBuffer = true;
                } else if( tn.equalsIgnoreCase(objects)) {
                    dumpObject = true;
                    dumpObjectHierarchy = true;
                    dumpObjectConstructors = true;
                    dumpObjectFields = true;
                    dumpObjectMethods = true;
                } else if( tn.equalsIgnoreCase(objectHierarchy)) {
                    dumpObject = true;
                    dumpObjectHierarchy = true;
                } else if( tn.equalsIgnoreCase(objectConstructors)) {
                    dumpObject = true;
                    dumpObjectConstructors = true;
                } else if( tn.equalsIgnoreCase(objectFields)) {
                    dumpObject = true;
                    dumpObjectFields = true;
                } else if( tn.equalsIgnoreCase(objectMethods)) {
                    dumpObject = true;
                    dumpObjectMethods = true;
                /*
                 * Properties that turn on debug trace
                 */
                } else if( tn.equalsIgnoreCase(all)) {
                    traceControls = true;
                    traceRawInput = true;
                    traceRawOutput = true;
                    traceReferrals = true;
                    traceMessages = true;
                    traceAPIRequests = true;
                    traceBindSemaphore = true;
                    traceUrlParse = true;
                    traceASN1 = true;
                    traceEncoding = true;
                    traceDecoding = true;
                    traceConnections = true;
                    traceSaslBind = true;
                    traceTLS = true;
                } else if( tn.equalsIgnoreCase(rawInput)) {
                    traceRawInput = toggle( traceRawInput);
                } else if( tn.equalsIgnoreCase(controls)) {
                    traceControls = toggle( traceControls);
                } else if( tn.equalsIgnoreCase(rawOutput)) {
                    traceRawOutput = toggle( traceRawOutput);
                } else if( tn.equalsIgnoreCase(referrals)) {
                    traceReferrals = toggle( traceReferrals);
                } else if( tn.equalsIgnoreCase(messages)) {
                    traceMessages = toggle( traceMessages);
                } else if( tn.equalsIgnoreCase(apiRequests)) {
                    traceMessages = toggle( traceAPIRequests);
                } else if( tn.equalsIgnoreCase(bindSemaphore)) {
                    traceMessages = toggle( traceBindSemaphore);
                } else if( tn.equalsIgnoreCase(urlParse)) {
                    traceUrlParse = toggle( traceUrlParse);
                } else if( tn.equalsIgnoreCase(asn1)) {
                    traceEncoding = toggle( traceASN1);
                } else if( tn.equalsIgnoreCase(encoding)) {
                    traceEncoding = toggle( traceEncoding);
                } else if( tn.equalsIgnoreCase(decoding)) {
                    traceDecoding = toggle( traceDecoding);
                } else if( tn.equalsIgnoreCase(connections)) {
                    traceConnections = toggle( traceConnections);
                } else if( tn.equalsIgnoreCase(TLS)) {
                    traceTLS = toggle(traceTLS);
                } else if( tn.equalsIgnoreCase(saslBind)) {
                    traceSaslBind = toggle(traceSaslBind);
                }
            }
        }
    }

    /**
     * Returns <code>true</code> if <code>trace</code> is enabled
     * @param type The String value of the trace type to check.
     */
    public static final boolean trace( String type)
    {
        if( LDAP_DEBUG) {
            if( type.equalsIgnoreCase(all)) {
                return (    traceRawInput  ||
                            traceRawOutput ||
                            traceReferrals ||
                            traceMessages  ||
                            traceBindSemaphore  ||
                            traceAPIRequests    ||
                            traceUrlParse  ||
                            traceASN1  ||
                            traceEncoding  ||
                            traceDecoding  ||
                            traceControls  ||
                            traceConnections ||
                            traceSaslBind ||
                            traceTLS);
            } else if( type.equalsIgnoreCase(rawInput)) {
                return(traceRawInput);
            } else if( type.equalsIgnoreCase(rawOutput)) {
                return(traceRawOutput);
            } else if( type.equalsIgnoreCase(referrals)) {
                return(traceReferrals);
            } else if( type.equalsIgnoreCase(messages)) {
                return(traceMessages);
            } else if( type.equalsIgnoreCase(apiRequests)) {
                return(traceAPIRequests);
            } else if( type.equalsIgnoreCase(bindSemaphore)) {
                return(traceBindSemaphore);
            } else if( type.equalsIgnoreCase(urlParse)) {
                return(traceUrlParse);
            } else if( type.equalsIgnoreCase(asn1)) {
                return(traceASN1);
            } else if( type.equalsIgnoreCase(encoding)) {
                return(traceEncoding);
            } else if( type.equalsIgnoreCase(decoding)) {
                return(traceDecoding);
            } else if( type.equalsIgnoreCase(controls)) {
                return(traceControls);
            } else if( type.equalsIgnoreCase(connections)) {
                return(traceConnections);
            } else if( type.equalsIgnoreCase(saslBind)) {
                return(traceSaslBind);
            } else if( type.equalsIgnoreCase(TLS)) {
                return(traceTLS);
	    } else if (type.equalsIgnoreCase(EventsCalls)){
		return (traceevents);
            }

            return false;
        } else {
            return false;
        }
    }
    
    /**
     * Sets the output PrintStream used for debug output
     *
     * @param stream The PrintStream used for debug output
     */
    public static final void setTraceStream( PrintStream stream)
    {
        debugOut = stream;
        return;
    }
    /**
     * Turns on or off debug printing
     * @param type The String value of the trace type to enable or disable.
     * @param val The boolean value to enable or disable <code>trace</code>.
     */
    public static final void setTrace( String type, boolean val)
    {
        if( LDAP_DEBUG) {
            if( type.equalsIgnoreCase(all)) {
                traceRawInput  = val;
                traceRawOutput = val;
                traceReferrals = val;
                traceMessages = val;
                traceAPIRequests = val;
                traceBindSemaphore = val;
                traceUrlParse  = val;
                traceASN1  = val;
                traceEncoding  = val;
                traceDecoding  = val;
                traceConnections = val;
                traceControls = val;
                traceSaslBind = val;
                traceTLS = val;
            } else if( type.equalsIgnoreCase(rawInput)) {
                traceRawInput = val;
            } else if( type.equalsIgnoreCase(controls)) {
                traceControls = val;
            } else if( type.equalsIgnoreCase(rawOutput)) {
                traceRawOutput = val;
            } else if( type.equalsIgnoreCase(referrals)) {
                traceReferrals = val;
            } else if( type.equalsIgnoreCase(messages)) {
                traceMessages = val;
            } else if( type.equalsIgnoreCase(apiRequests)) {
                traceAPIRequests = val;
            } else if( type.equalsIgnoreCase(bindSemaphore)) {
                traceBindSemaphore = val;
            } else if( type.equalsIgnoreCase(urlParse)) {
                traceUrlParse = val;
            } else if( type.equalsIgnoreCase(asn1)) {
                traceASN1 = val;
            } else if( type.equalsIgnoreCase(encoding)) {
                traceEncoding = val;
            } else if( type.equalsIgnoreCase(decoding)) {
                traceDecoding = val;
            } else if( type.equalsIgnoreCase(connections)) {
                traceConnections = val;
            } else if( type.equalsIgnoreCase(saslBind)) {
                traceSaslBind = val;
            } else if( type.equalsIgnoreCase(TLS)) {
                traceTLS = val;
            }
        }
        return;
    }
    /**
     * Displays the specified <code>String str</code> parameter to the
     * print stream if <code>trace</code> is enabled.
     * @param type    The String value of the trace type to print.
     * @param str    A string to display.
     *
     * @see #setTraceStream(PrintStream)
     */
    public static final void trace( String type, String str)
    {
        String tracing = "unknown";
        if( LDAP_DEBUG) {
            boolean printit = false;
            if( type.equalsIgnoreCase(all)) {
                printit =   traceRawInput  ||
                            traceRawOutput ||
                            traceReferrals ||
                            traceMessages  ||
                            traceAPIRequests    ||
                            traceBindSemaphore  ||
                            traceUrlParse  ||
                            traceEncoding  ||
                            traceASN1  ||
                            traceDecoding  ||
                            traceControls  ||
                            traceConnections ||
                            traceSaslBind ||
                            traceTLS;
                tracing="all";
            } else if( type.equalsIgnoreCase(rawInput)) {
                printit = traceRawInput;
                tracing="traceRawInput";
            } else if( type.equalsIgnoreCase(rawOutput)) {
                printit = traceRawOutput;
                tracing="traceRawOutput";
            } else if( type.equalsIgnoreCase(referrals)) {
                printit = traceReferrals;
                tracing="traceReferrals";
            } else if( type.equalsIgnoreCase(controls)) {
                printit = traceControls;
                tracing="traceControls";
            } else if( type.equalsIgnoreCase(messages)) {
                printit = traceMessages;
                tracing="traceMessages";
            } else if( type.equalsIgnoreCase(apiRequests)) {
                printit = traceAPIRequests;
                tracing="traceAPIRequests";
            } else if( type.equalsIgnoreCase(bindSemaphore)) {
                printit = traceBindSemaphore;
                tracing="traceBindSemaphore";
            } else if( type.equalsIgnoreCase(urlParse)) {
                printit = traceUrlParse;
                tracing="traceUrlParse";
            } else if( type.equalsIgnoreCase(asn1)) {
                printit = traceASN1;
                tracing="traceASN1";
            } else if( type.equalsIgnoreCase(encoding)) {
                printit = traceEncoding;
                tracing="traceEncoding";
            } else if( type.equalsIgnoreCase(decoding)) {
                printit = traceDecoding;
                tracing="traceDecoding";
            } else if( type.equalsIgnoreCase(connections)) {
                printit = traceConnections;
                tracing="traceConnections";
            } else if( type.equalsIgnoreCase(saslBind)) {
                printit = traceSaslBind;
                tracing="traceSaslBind";
            } else if( type.equalsIgnoreCase(TLS)) {
                printit = traceTLS;
                tracing="traceTLS";
             } else if (type.equalsIgnoreCase(EventsCalls)){
                printit = traceevents;
                tracing="traceEvents";
            }
            if( printit) {
                if( str == null) {
                    debugOut.println("  \nprintDebug: Cannot print NULL string");
                } else {
			        Date time = new Date();
			        String dateString = formatter.format(time);
                    debugOut.println( dateString + " " + tracing + ": " + str);
                }
            }
        }
        return;
    }

    /**
     * Returns <code>true</code> if <code>VMtraceInstructions</code> is enabled
     */
    public static final boolean VMtraceInstructions()
    {
        return VMtraceInstructions;
    }
    /**
    *    Displays trace of each instruction executed in the virtual machine
    * @param onOff    A boolean that when set to true enables instruction
    * tracing and when false disables instruction tracing.
    */
    public static final void VMtraceInstructions( boolean onOff)
    {
        if( LDAP_DEBUG) {
            if( VMtraceInstructions)
                run.traceInstructions( onOff);
        }
        return;
    }

    /**
     * Returns <code>true</code> if <code>VMtraceMethodCalls</code> is enabled
     */
    public static final boolean VMtraceMethodCalls()
    {
        return VMtraceMethodCalls;
    }
    /**
    *    Displays trace of each methods called
    * @param onOff    A boolean that when set to true enables method call
    * tracing and when false disables instruction tracing.
    */
    public static void VMtraceMethodCalls( boolean onOff)
    {
        if( LDAP_DEBUG) {
            if( VMtraceMethodCalls)
                run.traceMethodCalls( onOff);
        }
        return;
    }

    /**
    *    Returns the total memory available in the virtual machine
    */
    public static final long totalMemory( )
    {
        if( LDAP_DEBUG) {
            return run.totalMemory( );
        }
        return 0;
    }

    /**
    *    Returns the free memory available in the virtual machine
    */
    public static final long freeMemory( )
    {
        if( LDAP_DEBUG) {
            return run.freeMemory( );
        }
        return 0;
    }

    /**
     * Returns <code>true</code> if <code>dumpObect</code> is enabled
     */
    public static final boolean dumpObject()
    {
        return dumpObject;
    }
    /**
     * Turns on or off debug dumpObject
     * @param val The boolean value to enable or disable <code>dumpObject</code>.
     */
    public static final void setDumpObject( boolean val)
    {
        if( LDAP_DEBUG) {
            dumpObject = val;
            dumpObject = true;
            dumpObjectHierarchy = true;
            dumpObjectConstructors = true;
            dumpObjectFields = true;
            dumpObjectMethods = true;
        }
        return;
    }
    /**
     * Returns <code>true</code> if <code>dumpObjectHierarchy</code> is enabled
     */
    public static final boolean dumpObjectHierarchy()
    {
            return dumpObjectHierarchy;
    }
    /**
     * Turns on or off debug dumpObjectHierarchy
     * @param val The boolean value to enable or disable <code>dumpObjectHierarchy</code>.
     */
    public static final void setDumpObjectHierarchy( boolean val)
    {
        if( LDAP_DEBUG) {
            dumpObject = val;
            dumpObjectHierarchy = val;
        }
        return;
    }

    /**
     * Returns <code>true</code> if <code>dumpObectConstructors</code> is enabled
     */
    public static final boolean dumpObjectConstructors()
    {
        return dumpObjectConstructors;
    }
    /**
     * Turns on or off debug dumpObjectConstructors
     * @param val The boolean value to enable or disable <code>dumpObjectConstructors</code>.
     */
    public static final void setDumpObjectConstructors( boolean val)
    {
        if( LDAP_DEBUG) {
            dumpObject = val;
            dumpObjectConstructors = val;
        }
        return;
    }
    /**
     * Returns <code>true</code> if <code>dumpObjectFields</code> is enabled
     */
    public static final boolean dumpObjectFields()
    {
        return dumpObjectFields;
    }
    /**
     * Turns on or off debug dumpObjectFields
     * @param val The boolean value to enable or disable <code>dumpObjectFields</code>.
     */
    public static final void setDumpObjectFields( boolean val)
    {
        if( LDAP_DEBUG) {
            dumpObject = val;
            dumpObjectFields = val;
        }
        return;
    }
    /**
     * Returns <code>true</code> if <code>dumpObectMethods</code> is enabled
     */
    public static final boolean dumpObjectMethods()
    {
        return dumpObjectMethods;
    }
    /**
     * Turns on or off debug dumpObjectMethods
     * @param val The boolean value to enable or disable <code>dumpObjectMethods</code>.
     */
    public static final void setDumpObjectMethods( boolean val)
    {
        if( LDAP_DEBUG) {
            dumpObject = val;
            dumpObjectMethods = val;
        }
        return;
    }

    /**
    * Displays information about an object.  The amount of information displayed
    * is controlled by various environment variables or set methods. These are:
    * <li><b><code>dumpObject</code></b> - Displays all information about an object.
    * <li><b><code>dumpObjectHierarchy</code></b> - Displays object hierarchy</u>
    * <li><b><code>dumpObjectConstructors</code></b> - Displays object constructors</u>
    * <li><b><code>dumpObjectFields</code></b> - Displays object fields</u>
    * <li><b><code>dumpObjectMethods</code></b> - Displays object methods</u>
    * </ul>
    * <p>
    * Multiple environment values are separated by semicolon's, i.e.
    * <ul>
    * <code>java -Dldap.debug=serverprogress;echodebug TServer -tree junk</code>
    *  <p>or</p>
    * <code>java -Dldap.debug=TraceAll TServer -tree junk</code>
    * </ul>
    * @param obj The object to dump
    */
    public static final void dumpObject( Object obj)
    {
        if( LDAP_DEBUG) {
            int level = 2;

            if( obj == null) {
                debugOut.println("  \ndumpObject: No class information obtainable for NULL class");
                return;
            }
            if( ! dumpObject)
                return;
            // Print object name
            Class theClass = obj.getClass();
            if( theClass == null)
            {
                debugOut.println("\ndumpObject: No class information obtainable for "
                    + obj.toString());
                return;
            }
            Class oldClass = (Class)objprop.put( theClass.getName(), theClass);
            if( oldClass != null)
                return;        // We have already reported on this class
            debugOut.println("\nV------------------------------------------------------------------------------V");
            debugOut.println("Object of class  " + theClass.getName());
            // Print toString info
            debugOut.println("\n  " + obj.toString() + "\n");

            if( dumpObjectHierarchy) {
                // Print getDeclaredClasses info
                Class Dclasses[] = theClass.getDeclaredClasses();
                debugOut.println("  Classes returned by getDeclaredClasses is "
                    + Dclasses.length);
                for( int i = 1; i <= Dclasses.length; i++)
                {
                    debugOut.println("      " + i + " " + Dclasses[i-1].getName());
                }
                // Print getDeclaringClass info
                Class DCclass = theClass.getDeclaringClass();
                if( DCclass == null)
                {
                    debugOut.println("  Class returned by getDeclaringClass is null");
                } else {
                    debugOut.println("  Class returned by getDeclaringClass is "
                        + DCclass.getName());
                }
                // Print Signers of class
                Object gsigners[] = theClass.getSigners();
                if( gsigners == null)
                {
                    debugOut.println("  Signers returned by getSigners is null");
                }
                else
                {
                    debugOut.println("  Signers returned by getSigners is "
                        + gsigners.length);
                    for( int i = 1; i <= gsigners.length; i++)
                    {
                        debugOut.println("      " + i + " "
                            +  gsigners[i-1].toString());
                    }
                }
                // Print getClasses info
                Class classes[] = theClass.getClasses();
                debugOut.println("  Classes returned by getClasses is "
                    + classes.length);
                for( int i = 1; i <= classes.length; i++)
                {
                    debugOut.println("      " + i + " " + classes[i-1].getName());
                }
                // Print object class hierarchy
                Class superClass = theClass;
                debugOut.println("\n  Class Hierarchy");
                dumpClasses( superClass, level);
            }

            if( dumpObjectConstructors) {
                // Print getGetConstructors
                Constructor constructors[] = theClass.getConstructors();
                debugOut.println("  Constructors returned by getConstructors is "
                    + constructors.length);
                for( int i = 1; i <= constructors.length; i++)
                {
                    debugOut.println("      " + i + " "
                        + constructors[i-1].getName()
                        + ": " + constructors[i-1].toString());
                }
                // Print getGetDeclaredConstructors
                Constructor dconstructors[] = theClass.getDeclaredConstructors();
                debugOut.println(
                    "  Declared Constructors returned by getDeclaredConstructors is "
                    + dconstructors.length);
                for( int i = 1; i <= dconstructors.length; i++)
                {
                    debugOut.println("      " + i + " "
                        + dconstructors[i-1].getName() + ": "
                        + dconstructors[i-1].toString());
                }
            }
            if( dumpObjectFields) {
                // Print getFields
                Field gfields[] = theClass.getFields();
                debugOut.println("  Fields returned by getFields is "
                    + gfields.length);
                for( int i = 1; i <= gfields.length; i++)
                {
                    Class fieldClass;
                    debugOut.println("      " + i + " " + gfields[i-1].getName()
                        + ": " + gfields[i-1].toString());
                    fieldClass = gfields[i-1].getType();
                    if( ! fieldClass.isPrimitive())
                        dumpClasses( fieldClass, level+2);
                }
                // Print getDeclared Fields
                Field dfields[] = theClass.getDeclaredFields();
                debugOut.println("  Fields returned by getDeclaredFields is "
                    + dfields.length);
                for( int i = 1; i <= dfields.length; i++)
                {
                    Class fieldClass;
                    debugOut.println("      " + i + " " + dfields[i-1].getName()
                        + ": " + dfields[i-1].toString());
                    fieldClass = dfields[i-1].getType();
                    if( ! fieldClass.isPrimitive())
                        dumpClasses( fieldClass, level+2);
                }
            }

            if( dumpObjectMethods) {
                // Print getMethods
                try {
                    Method gmethods[] = theClass.getMethods();
                    debugOut.println("  Methods returned by getMethods is "
                        + gmethods.length);
                    for( int i = 1; i <= gmethods.length; i++)
                    {
                        debugOut.println("      " + i + " " + gmethods[i-1].getName()
                            + ": " + gmethods[i-1].toString());
                    }
                } catch( NoClassDefFoundError e) {
                    debugOut.println("  getMethods returned NoClassDefFoundError Exception " + e.toString());
                }
                // Print getDeclared Methods
                try {
                    Method dmethods[] = theClass.getDeclaredMethods();
                    debugOut.println("  Methods returned by getDeclaredMethods is "
                        + dmethods.length);
                    for( int i = 1; i <= dmethods.length; i++)
                    {
                        debugOut.println("      " + i + " " + dmethods[i-1].getName()
                            + ": " + dmethods[i-1].toString());
                    }
                } catch( NoClassDefFoundError e) {
                    debugOut.println("  getDeclaredMethods returned NoClassDefFoundError Exception " + e.toString());
                }
            }
            debugOut.println("\n^------------------------------------------------------------------------------^");
        }
        return;
    }

    // Print Interface heirarchy
    static private final void dumpInterfaces( Class obj, int level)
    {
        if( LDAP_DEBUG) {
            Class sinterfaces[] = obj.getInterfaces();
            for( int i = 1; i <= sinterfaces.length; i++)
            {
                for( int j = 0; j < level; j++)
                    debugOut.print("  ");
                debugOut.println(sinterfaces[i-1].toString());
                dumpInterfaces( sinterfaces[i-1], level+1);
            }
        }
        return;
    }

    // Print Class heirarchy
    static private final void dumpClasses( Class obj, int level)
    {
        if( LDAP_DEBUG) {
            do
            {
                for( int j = 0; j < level; j++)
                     debugOut.print("  ");
                debugOut.println( obj.toString());
                dumpInterfaces(  obj, level+1);
            } while( ( obj =  obj.getSuperclass()) != null);
        }
        return;
    }

    /**
     * Returns <code>true</code> if <code>dumpBuffer</code> is enabled
     */
    public static final boolean dumpBuffer()
    {
        return dumpBuffer;
    }
    /**
     * Turns on or off debug dumpBuffer
     * @param val The boolean value to enable or disable <code>dumpBuffer</code>.
     */
    public static final void setDumpBuffer( boolean val)
    {
        if( LDAP_DEBUG) {
            dumpBuffer = val;
        }
        return;
    }

    /**
    *    Dumps a the specified portion of the byte array, as hexidecmal bytes
    *   and also intrepreted as ASCII.
    *    @param msg The title to display before the buffer dump
    *   @param inBuffer The byte arrary buffer to dump
    *   @param fileOffset The address displayed is offset by this amount
    *   @param length The number of bytes to display
    *
    */
    static public final void dumpBuffer( String msg, byte[] inBuffer, int fileOffset, int length)
    {
        if( LDAP_DEBUG) {
            int byteCnt = 0;
            byte[] tstLine = new byte[16];    // Place to store the test line
            boolean haveTstLine = false;    // Test line stored
            boolean matchTstLine = false;    // Current line matches test line
            boolean matchLastLine = false;    // Previous line matches test line

            if( !dumpBuffer)
                return;
            debugOut.println( msg);
            while( byteCnt < length) {
                if( (byteCnt + 16) >= length - 1) { // Always print the last line
                    if( matchLastLine) {
                        debugOut.println("******");
                    }
                    matchTstLine = false;
                } else {                            // Not the last line
                    if( haveTstLine) {
                        matchTstLine = false;        // Assume we don't have a match
                        for( int i = 0; i < 16; i++) {
                            if(tstLine[i] != inBuffer[byteCnt + i]) {
                                if( matchLastLine) {    // print ***** for skips
                                    debugOut.println("******");
                                }
                                haveTstLine = false;
                                matchLastLine = false;
                                matchTstLine = false;
                                break;
                            }
                        }
                        matchLastLine = true;        // Make sure prev line set for next loop
                        matchTstLine = true;        // Assume we have a match
                    }
                    if( ! haveTstLine) {            // Get a test line if needed
                        for( int i = 0; i < 16; i++) {
                            tstLine[i] = inBuffer[byteCnt + i];
                        }
                        haveTstLine = true;
                        matchTstLine = false;
                        matchLastLine = false;
                    }
                }
                if( matchTstLine) {
                    byteCnt += 16;
                    continue;
                }
                dumpLine( inBuffer, byteCnt, length, fileOffset);
                byteCnt += 16;
                continue;
            }
        }
        return;
    } // dumpBuffer

    private static final void dumpLine( byte[] inBuffer, int offset, int length, int addrOffset)
    {
        if( LDAP_DEBUG) {
            byte DOT = 0x2e;                // ascii period
            byte SP = 0x20;                // ascii space
            String hexDigits;
            int byteCnt = offset;
            int itemCnt;

            String address = Integer.toHexString( offset + addrOffset);
            while( address.length() < 6) {
                address = "0" + address;
            }
            debugOut.print( address + "    ");
            for( itemCnt = 0; itemCnt < 16; itemCnt++) {
                hexDigits = Integer.toHexString( inBuffer[byteCnt]);
                byteCnt++;
                if( hexDigits.length() > 2) {
                    hexDigits = hexDigits.substring( hexDigits.length()-2, hexDigits.length());
                }
                if( hexDigits.length() == 2) {
                    debugOut.print( hexDigits + " ");
                } else {
                    debugOut.print( "0" + hexDigits + " ");
                }
                if( itemCnt == 7) {
                    debugOut.print(" ");
                }
                // Check for last byte
                if( byteCnt == length) {
                    itemCnt++;            // Make sure count of items is correct
                    break;
                }
            }
            // Copy the characters previously printed.  We will now print them
            // in character format.  We copy the array as we are going to modify
            // the non printable characters and add a count at the beginning.
            byte[] b = new byte[itemCnt + 2];
            b[0] = 0;
            b[1] = (byte)itemCnt;
            for( int i = 0; i < itemCnt; i++) {
                // Prepare for printing character - make sure doesn't intrepret
                // as Unicode
                if( inBuffer[offset+i] < SP) {
                    b[i+2] = DOT;
                } else {
                    b[i+2] = inBuffer[offset+i];
                }
            }
            try {
                DataInputStream dataStream =
                        new DataInputStream(
                        new ByteArrayInputStream(b));
                debugOut.println(dataStream.readUTF());
            } catch( Exception e) {
                debugOut.println(e.toString());
                debugOut.println(e.getMessage());
                System.exit(1);
            }
        }
        return;
    }
} // Debug
