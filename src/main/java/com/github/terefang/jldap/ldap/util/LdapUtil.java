package com.github.terefang.jldap.ldap.util;

import com.github.terefang.jldap.ldap.*;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.util.*;

@Slf4j
public class LdapUtil {

    public static LDAPConnection connectTo(String _url, LDAPSocketFactory _sf) throws LDAPException
    {
        URI _uri = URI.create(_url);
        return connectTo(_uri.getHost(), _uri.getPort(), _sf);
    }

    public static LDAPConnection connectTo(String _host, int _port, LDAPSocketFactory _sf) throws LDAPException
    {
        LDAPConnection _connection = null;
        if(_sf==null)
        {
            _connection = new LDAPConnection();
        }
        else
        {
            _connection = new LDAPConnection(_sf);
        }
        _connection.connect(_host, _port);
        return _connection;
    }

    public static boolean authenticate(LDAPConnection _conn, String _dn, String _pw) throws LDAPException {
        try
        {
            _conn.bind(LDAPConnection.LDAP_V3, _dn, _pw.getBytes(StandardCharsets.UTF_8));
            return true;
        }
        catch (LDAPException _xe)
        {
            log.warn(MessageFormat.format("authentication error dn={0}. {1}", _dn, _xe.getMessage()));
        }
        return false;
    }

    @SneakyThrows
    public static List<Map<String, List<String>>> searchEntries(LDAPConnection _conn, String _base, String _filter, String... _ra)
    {
        List<Map<String, List<String>>> _ret = new Vector<>();
        LDAPSearchResults _res = _conn.search(_base, LDAPConnection.SCOPE_SUB, _filter, _ra, false);
        while(_res.hasMore())
        {
            LDAPEntry _row = _res.next();
            _ret.add(parseEntry(_row));
        }
        return _ret;
    }

    @SneakyThrows
    public static Map<String, List<String>> searchEntry(LDAPConnection _conn, String _base, String _filter, String... _ra)
    {
        LDAPSearchResults _res = _conn.search(_base, LDAPConnection.SCOPE_SUB, _filter, _ra, false);
        if(_res.hasMore())
        {
            LDAPEntry _row = _res.next();
            return parseEntry(_row);
        }
        return null;
    }

    @SneakyThrows
    public static Map<String, List<String>> getEntry(LDAPConnection _conn, String _base, String... _ra)
    {
        LDAPSearchResults _res = _conn.search(_base, LDAPConnection.SCOPE_BASE, "(objectClass=*)", _ra, false);
        if(_res.hasMore())
        {
            LDAPEntry _row = _res.next();
            return parseEntry(_row);
        }
        return null;
    }

    public static Map<String, List<String>> parseEntry(LDAPEntry _row)
    {
        Map<String, List<String>> _rrow = new HashMap<>();
        _rrow.put("dn", Collections.singletonList(_row.getDN()));
        _row.getAttributeSet().forEach((x) -> {
            String _name = ((LDAPAttribute) x).getName();
            String[] _values = ((LDAPAttribute) x).getStringValueArray();
            _rrow.put(_name, Arrays.asList(_values));
        });
        return _rrow;
    }

    public static void close(LDAPConnection _conn)
    {
        try
        {
            _conn.disconnect();
        }
        catch (LDAPException _xe)
        {
            log.warn(MessageFormat.format("connection close failed. {0}", _xe.getMessage()));
        }
    }
}
