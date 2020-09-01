package com.github.terefang.jldap.ldap.ssl;

import com.github.terefang.jldap.ldap.LDAPConnection;
import com.github.terefang.jldap.ldap.LDAPException;
import com.github.terefang.jldap.ldap.util.LdapUtil;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.UnknownHostException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Slf4j
public class LdapSslUtil extends LdapUtil
{
    public static LDAPConnection connectTlsTo(String _url, SSLSocketFactory _sf) throws LDAPException
    {
        URI _uri = URI.create(_url);
        return connectTlsTo(_uri.getHost(), _uri.getPort(), _sf);
    }

    public static LDAPConnection connectTlsTo(String _host, int _port, SSLSocketFactory _sf) throws LDAPException
    {
        if(_sf==null)
        {
            _sf = createSSLSocketFactory();
        }
        LDAPJSSESecureSocketFactory _factory = new LDAPJSSESecureSocketFactory(_sf);
        LDAPConnection _connection = new LDAPConnection(_factory);
        _connection.connect(_host, _port);
        return _connection;
    }

    public static LDAPConnection connectStlsTo(String _url, SSLSocketFactory _sf) throws LDAPException
    {
        URI _uri = URI.create(_url);
        return connectStlsTo(_uri.getHost(), _uri.getPort(), _sf);
    }

    public static LDAPConnection connectStlsTo(String _host, int _port, SSLSocketFactory _sf) throws LDAPException
    {
        if(_sf==null)
        {
            _sf = createSSLSocketFactory();
        }
        LDAPJSSEStartTLSFactory _factory = new LDAPJSSEStartTLSFactory(_sf);
        LDAPConnection _connection = new LDAPConnection(_factory);
        _connection.connect(_host, _port);
        _connection.startTLS();
        return _connection;
    }

    public static SSLSocketFactory createSSLSocketFactory()
    {
        SSLSocketFactory _sf = new SSLSocketFactory()
        {
            private SSLContext _context = createSSLContext(false);
            private SSLParameters _parameters = createSSLParameters();

            @Override
            public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
                return customizeSocket((SSLSocket) _context.getSocketFactory().createSocket(host, port));
            }

            @Override
            public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException {
                return customizeSocket((SSLSocket) _context.getSocketFactory().createSocket(host, port, localHost, localPort));
            }

            @Override
            public Socket createSocket(InetAddress host, int port) throws IOException {
                return customizeSocket((SSLSocket) _context.getSocketFactory().createSocket(host, port));
            }

            @Override
            public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
                return customizeSocket((SSLSocket) _context.getSocketFactory().createSocket(address, port, localAddress, localPort));
            }

            @Override
            public String[] getDefaultCipherSuites() {
                return _context.getDefaultSSLParameters().getCipherSuites();
            }

            @Override
            public String[] getSupportedCipherSuites() {
                return _context.getSupportedSSLParameters().getCipherSuites();
            }

            @Override
            public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
                return customizeSocket((SSLSocket) _context.getSocketFactory().createSocket(s, host, port, autoClose));
            }

            Socket customizeSocket(SSLSocket _socket)
            {
                _socket.setUseClientMode(true);
                _socket.setSSLParameters(_parameters);
                return _socket;
            }
        };
        return _sf;
    }

    public static SSLParameters createSSLParameters()
    {
        SSLParameters _p = new SSLParameters();
        return _p;
    }

    @SneakyThrows
    public static SSLContext createSSLContext(final boolean _verbose)
    {
        SSLContext _ctx = SSLContext.getInstance("TLS");

        KeyManager[] _km = new KeyManager[0];

        TrustManager[] _tm = new TrustManager[1];
        _tm[0] = new X509ExtendedTrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
                if(!_verbose) return;
                log.info(MessageFormat.format("checkClientTrusted : {0}", authType));
                for(X509Certificate _cert : chain)
                {
                    log.info(MessageFormat.format("cert: subject={0} issuer={1}\n{2}", _cert.getSubjectDN().getName(), _cert.getIssuerDN().getName(), _cert.toString()));
                }
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
                if(!_verbose) return;
                log.info(MessageFormat.format("checkServerTrusted : {0}", authType));
                for(X509Certificate _cert : chain)
                {
                    log.info(MessageFormat.format("cert: subject={0} issuer={1}\n{2}", _cert.getSubjectDN().getName(), _cert.getIssuerDN().getName(), _cert.toString()));
                }
            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
                if(!_verbose) return;
                log.info(MessageFormat.format("checkClientTrusted : {0}", authType));
                for(X509Certificate _cert : chain)
                {
                    log.info(MessageFormat.format("cert: subject={0} issuer={1}\n{2}", _cert.getSubjectDN().getName(), _cert.getIssuerDN().getName(), _cert.toString()));
                }
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
                if(!_verbose) return;
                log.info(MessageFormat.format("checkServerTrusted : {0}", authType));
                for(X509Certificate _cert : chain)
                {
                    log.info(MessageFormat.format("cert: subject={0} issuer={1}\n{2}", _cert.getSubjectDN().getName(), _cert.getIssuerDN().getName(), _cert.toString()));
                }
            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                if(!_verbose) return;
                log.info(MessageFormat.format("checkClientTrusted : {0}", authType));
                for(X509Certificate _cert : chain)
                {
                    log.info(MessageFormat.format("cert: subject={0} issuer={1}\n{2}", _cert.getSubjectDN().getName(), _cert.getIssuerDN().getName(), _cert.toString()));
                }
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                if(!_verbose) return;
                log.info(MessageFormat.format("checkServerTrusted : {0}", authType));
                for(X509Certificate _cert : chain)
                {
                    log.info(MessageFormat.format("cert: subject={0} issuer={1}\n{2}", _cert.getSubjectDN().getName(), _cert.getIssuerDN().getName(), _cert.toString()));
                }
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };

        _ctx.init(_km, _tm, null);

        return _ctx;
    }

    @SneakyThrows
    public static void main(String[] args) {
        //System.setProperty("javax.net.debug", "all");
        log.info("start");
        LDAPConnection _c = LdapSslUtil.connectStlsTo("ldap.forumsys.com", 389, null);
        boolean _r = LdapSslUtil.authenticate(_c, "cn=read-only-admin,dc=example,dc=com", "password");
        log.info(Objects.toString(_r));

        List<Map<String, List<String>>> _res = LdapSslUtil.searchEntries(_c, "dc=example,dc=com", "(ObjectClass=*)", "cn", "objectClass");

        for(Map<String, List<String>> _row : _res)
        {
            log.info(Objects.toString(_row));
        }

        Map<String, List<String>> _res2 = LdapSslUtil.getEntry(_c, "cn=read-only-admin,dc=example,dc=com", "*");
        log.info(Objects.toString(_res2));

        LdapSslUtil.close(_c);
        log.info("stop");
    }
}
