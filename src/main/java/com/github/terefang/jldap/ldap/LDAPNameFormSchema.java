/* **************************************************************************
 * $OpenLDAP:
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
package com.github.terefang.jldap.ldap;

import java.io.IOException;
import java.util.Enumeration;

import com.github.terefang.jldap.ldap.client.AttributeQualifier;
import com.github.terefang.jldap.ldap.client.SchemaParser;
/**
 * A specific a name form in the directory schema.
 *
 * <p>The LDAPNameFormSchema class represents the definition of a Name Form.  It
 * is used to discover or modify the allowed naming attributes for a particular
 * object class.</p>
 *
 * @see LDAPSchemaElement
 * @see LDAPSchema
 */

public class LDAPNameFormSchema
                extends LDAPSchemaElement
{
    private String objectClass;
    private String[] required;
    private String[] optional;

	/**
	 * This constructor was added to support default Serialization
	 *
	 */
	public LDAPNameFormSchema()
	{
		super(LDAPSchema.schemaTypeNames[LDAPSchema.NAME_FORM]);    
		super.obsolete = false;
	}
	
    /**
     * Constructs a name form for adding to or deleting from the schema.
     *
     * @param names       The name(s) of the name form.</br></br>
     *
     * @param oid         The unique object identifier of the name form - in
     *                    dotted numerical format.</br></br>
     *
     * @param description An optional description of the name form.</br></br>
     *
     * @param obsolete    True if the name form is obsolete.</br></br>
     *
     * @param objectClass The object to which this name form applies.
     *                    This may be specified by either name or
     *                    numeric oid.</br></br>
     *
     * @param required    A list of the attributes that must be present
     *                    in the RDN of an entry that this name form
     *                    controls. These attributes may be specified by
     *                    either name or numeric oid.</br></br>
     *
     * @param optional    A list of the attributes that may be present
     *                    in the RDN of an entry that this name form
     *                    controls. These attributes may be specified by
     *                    either name or numeric oid.</br></br>
     */
    public LDAPNameFormSchema(String[] names,
                              String oid,
                              String description,
                              boolean obsolete,
                              String objectClass,
                              String[] required,
                              String[] optional)
    {
        super(LDAPSchema.schemaTypeNames[LDAPSchema.NAME_FORM]);
        super.names = (String[]) names.clone();
        super.oid = oid;
        super.description = description;
        super.obsolete = obsolete;
        this.objectClass = objectClass;
        this.required = (String[])required.clone();
        this.optional = (String[])optional.clone();
        super.setValue( formatString() );
        return;
    }

    /*
    }

    /**
     * Constructs a Name Form from the raw string value returned on a
     * schema query for nameForms.
     *
     * @param raw        The raw string value returned on a schema
     *                   query for nameForms.
     */
    public LDAPNameFormSchema(String raw)
    {
        super(LDAPSchema.schemaTypeNames[LDAPSchema.NAME_FORM]);    
        super.obsolete = false;
        try{
            SchemaParser parser = new SchemaParser( raw );

            if( parser.getNames() != null)
                super.names = (String[])parser.getNames().clone();
            if( parser.getID() != null)
                super.oid = new String(parser.getID());
            if( parser.getDescription() != null)
                super.description = new String(parser.getDescription());
            if( parser.getRequired() != null)
                required = (String[])parser.getRequired().clone();
            if( parser.getOptional() != null)
                optional = (String[])parser.getOptional().clone();
            if( parser.getObjectClass() != null)
                objectClass = parser.getObjectClass();
            super.obsolete = parser.getObsolete();
            Enumeration qualifiers = parser.getQualifiers();
            AttributeQualifier attrQualifier;
            while(qualifiers.hasMoreElements()){
                attrQualifier = (AttributeQualifier) qualifiers.nextElement();
                setQualifier(attrQualifier.getName(), attrQualifier.getValues());
            }
            super.setValue( formatString() );
        }
        catch( IOException e){
        }
        return;
    }

    /**
     * Returns the name of the object class which this name form applies to.
     *
     * @return The name of the object class.
     */
    public String getObjectClass()
    {
        return objectClass;
    }


    /**
     * Returns the list of required naming attributes for an entry
     * controlled by this name form.
     *
     * @return The list of required naming attributes.
     */
    public String[]getRequiredNamingAttributes()
    {
        return required;
    }

    /**
     * Returns the list of optional naming attributes for an entry
     * controlled by this content rule.
     *
     * @return The list of the optional naming attributes.
     */
    public String[]getOptionalNamingAttributes()
    {
        return optional;
    }

    /**
    * Returns a string in a format suitable for directly adding to a
    * directory, as a value of the particular schema element class.
    *
    * @return A string representation of the class' definition.
    */
   protected String formatString()
   {
      StringBuffer valueBuffer = new StringBuffer("( ");
      String token;
      String[] strArray;

      if( (token = getID()) != null){
        valueBuffer.append(token);
      }
      strArray = getNames();
      if( strArray != null){
        valueBuffer.append(" NAME ");
        if (strArray.length == 1){
            valueBuffer.append("'" + strArray[0] + "'");
        }
        else {
           valueBuffer.append("( ");

           for( int i = 0; i < strArray.length; i++ ){
               valueBuffer.append(" '" + strArray[i] + "'");
           }
           valueBuffer.append(" )");
        }
      }
      if( (token = getDescription()) != null){
        valueBuffer.append(" DESC ");
        valueBuffer.append("'" + token + "'");
      }
      if( isObsolete()){
        valueBuffer.append(" OBSOLETE");
      }
      if( (token = getObjectClass()) != null){
        valueBuffer.append(" OC ");
        valueBuffer.append("'" + token + "'");
      }
      if( (strArray = getRequiredNamingAttributes()) != null){
          valueBuffer.append(" MUST ");
           if( strArray.length > 1)
            valueBuffer.append("( ");
        for( int i =0; i < strArray.length; i++){
            if( i > 0)
                 valueBuffer.append(" $ ");
               valueBuffer.append(strArray[i]);
        }
        if( strArray.length > 1)
            valueBuffer.append(" )");
      }
      if( (strArray = getOptionalNamingAttributes()) != null){
          valueBuffer.append(" MAY ");
          if( strArray.length > 1)
               valueBuffer.append("( ");
        for( int i =0; i < strArray.length; i++){
            if( i > 0)
                 valueBuffer.append(" $ ");
               valueBuffer.append(strArray[i]);
        }
        if( strArray.length > 1)
            valueBuffer.append(" )");
      }
      Enumeration en;
      if( (en = getQualifierNames()) != null){
          String qualName;
           String[] qualValue;
          while( en.hasMoreElements() ) {
               qualName = (String)en.nextElement();
             valueBuffer.append( " " + qualName + " ");
              if((qualValue = getQualifier( qualName )) != null){
                   if( qualValue.length > 1)
                         valueBuffer.append("( ");
                           for(int i = 0; i < qualValue.length; i++ ){
                              if( i > 0 )
                                   valueBuffer.append(" ");
                            valueBuffer.append( "'" + qualValue[i] + "'");
                          }
                       if( qualValue.length > 1)
                           valueBuffer.append(" )");
                }
          }
      }
      valueBuffer.append(" )");
      return valueBuffer.toString();
   }

}
