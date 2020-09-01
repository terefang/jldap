/* **************************************************************************
 * $OpenLDAP$
 *
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

package com.github.terefang.jldap.ldap;

import java.io.IOException;

import com.github.terefang.jldap.ldap.util.Base64;
/**
 * A single add, delete, or replace operation to an LDAPAttribute.
 *
 * <p>An LDAPModification contains information on the type of modification
 * being performed, the name of the attribute to be replaced, and the new
 * value.  Multiple modifications are expressed as an array of modifications,
 * i.e., <code>LDAPModification[]</code>.</p>
 *
 * <p>An LDAPModification or an LDAPModification array enable you to modify
 * an attribute of an LDAP entry. The entire array of modifications must
 * be performed by the server as a single atomic operation in the order they
 * are listed. No changes are made to the directory unless all the operations
 * succeed. If all succeed, a success result is returned to the application.
 * It should be noted that if the connection fails during a modification,
 * it is indeterminate whether the modification occurred or not.</p>
 *
 * <p>There are three types of modification operations: Add, Delete,
 * and Replace.</p>
 *
 * <p><b>Add: </b>Creates the attribute if it doesn't exist, and adds
 * the specified values. This operation must contain at least one value, and
 * all values of the attribute must be unique.</p>
 *
 * <p><b>Delete: </b>Deletes specified values from the attribute. If no
 * values are specified, or if all existing values of the attribute are
 * specified, the attribute is removed. Mandatory attributes cannot be
 * removed.</p>
 *
 * <p><b>Replace: </b>Creates the attribute if necessary, and replaces
 * all existing values of the attribute with the specified values.
 * If you wish to keep any existing values of a multi-valued attribute,
 * you must include these values in the replace operation.
 * A replace operation with no value will remove the entire attribute if it
 * exists, and is ignored if the attribute does not exist.</p>
 *
 * <p>Additional information on LDAP modifications is available in section 4.6
 * of <a href="http://www.ietf.org/rfc/rfc2251.txt">rfc2251.txt</a></p>
 *
 *  <p>Sample Code:
 *     <DT>Adding, replacing, or deleting individual attribute values
 *     <DD><a href="http://developer.novell.com/ndk/doc/samplecode/jldap_sample/jldap_sample/ModifyAttrs.java.html">ModifyAttrs.java</a></DD></DT></p>
 *
 *     <p><DT>Deleting an attribute
 *     <DD><a href="http://developer.novell.com/ndk/doc/samplecode/jldap_sample/jldap_sample/DeleteAttribute.java.html">DeleteAttribute.java</a></DD></DT></p>
 *
 * @see LDAPConnection#modify
 * @see LDAPAttribute
 */
public class LDAPModification {

   private int op;
   private LDAPAttribute attr;

   /**
	* Adds the listed values to the given attribute, creating
	* the attribute if it does not already exist.
	*
	*<p>ADD = 0</p>
	*/
   public static final int ADD = 0;

   /**
	* Deletes the listed values from the given attribute,
	* removing the entire attribute (1) if no values are listed or
	* (2) if all current values of the attribute are listed for
	* deletion.
	*
	*<p>DELETE = 1</p>
	*/
   public static final int DELETE = 1;

   /**
	* Replaces all existing values of the given attribute
	* with the new values listed, creating the attribute if it
	* does not already exist.
	*
	* <p> A replace with no value deletes the entire attribute if it
	*  exists, and is ignored if the attribute does not exist. </p>
	*
	*<p>REPLACE = 2</p>
	*/
   public static final int REPLACE = 2;

   /**
	* This constructor was added to support default Serialization
	*
	*/
   public LDAPModification()
   {
	   super();
   }
   
   /**
	* Specifies a modification to be made to an attribute.
	*
	*  @param op       The type of modification to make, which can be
	*                  one of the following:
	*<ul>
	*         <li>LDAPModification.ADD - The value should be added to
	*                                    the attribute</li>
	*
	*         <li>LDAPModification.DELETE - The value should be removed
	*                                       from the attribute </li>
	*
	*         <li>LDAPModification.REPLACE - The value should replace all
	*                                        existing values of the
	*                                        attribute </li>
	*</ul><br>
	*  @param attr     The attribute to modify.
	*
	*/
   public LDAPModification(int op, LDAPAttribute attr)
   {
	  this.op = op;
	  this.attr = attr;
	  return;
   }

   /**
	* Returns the attribute to modify, with any existing values.
	*
	* @return The attribute to modify.
	*/
   public LDAPAttribute getAttribute()
   {
	  return attr;
   }

   /**
	* Returns the type of modification specified by this object.
	*
	* <p>The type is one of the following:</p>
	* <ul>
	*   <li>LDAPModification.ADD</li>
	*   <li>LDAPModification.DELETE</li>
	*   <li>LDAPModification.REPLACE</li>
	* </ul>
	*
	* @return The type of modification specified by this object.
	*/
   public int getOp()
   {
	  return op;
   }
   
	void newLine(int indentTabs,java.io.Writer out) throws java.io.IOException
	{
		String tabString = "    ";    
        
		out.write("\n");
		for (int i=0; i< indentTabs; i++){
			out.write(tabString);
		}
		return;
	}
   
	/**
	 * This method does DSML serialization of the instance.
	 *
	 * @param oout Outputstream where the serialzed data has to be written
	 *
	 * @throws IOException if write fails on OutputStream 
	 */    
	public void writeDSML(java.io.OutputStream oout) throws java.io.IOException
	{
		java.io.Writer out=new java.io.OutputStreamWriter(oout,"UTF-8");
		out.write("<modification name=\"");
		out.write(attr.getName());
		out.write("\" operation=\"");
		switch(getOp())
		{
			case LDAPModification.ADD:
				out.write("add");
				break;

			case LDAPModification.DELETE:
				out.write("delete");
				break;

			case LDAPModification.REPLACE:
				out.write("replace");
				break;
		}
                    
		out.write("\">");
		LDAPAttribute attr=getAttribute();
		String values[] = attr.getStringValueArray();
		byte bytevalues[][] = attr.getByteValueArray();
			for(int j=0; j<values.length; j++){
				newLine(1,out);
				if (Base64.isValidUTF8(bytevalues[j], false)){
					out.write("<value>");
					out.write(values[j]);
					out.write("</value>");
				} else {
					out.write("<value xsi:type=\"xsd:base64Binary\">");
					out.write(Base64.encode(bytevalues[j]));
					out.write("</value>");
				}

			}
		newLine(0,out);
		out.write("</modification>");
		out.close();
	}

	/**
	 * Returns a  string representation of this class.
	 *
	 * @return The string representation of this class.
	 */
	public String toString()
		{
			StringBuffer result = new StringBuffer("LDAPModification: (operation=");
			switch(getOp())
			{
				case LDAPModification.ADD:
					result.append("add");
					break;

				case LDAPModification.DELETE:
					result.append("delete");
					break;

				case LDAPModification.REPLACE:
					result.append("replace");
					break;
			}
			result.append(",("+getAttribute()+"))");
			return result.toString();
		}


}
