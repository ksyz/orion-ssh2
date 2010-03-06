/*
 * StreamTransportManager.java
 *
 * Created on April 14, 2007, 7:53 PM
 */

package com.trilead.ssh2.transport;

import com.trilead.ssh2.DHGexParameters;
import com.trilead.ssh2.LocalStreamForwarder;
import com.trilead.ssh2.ProxyData;
import com.trilead.ssh2.ServerHostKeyVerifier;
import com.trilead.ssh2.crypto.CryptoWishList;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

/**
 *
 * @author Juraj Bednar, juraj.bednar@digmia.com
 */
public class StreamTransportManager extends GenericTransportManager {
    
    private LocalStreamForwarder stream = null;
    
    public StreamTransportManager(String host, int port) {
        super(host, port);
    }
    
    public StreamTransportManager(String host, int port, LocalStreamForwarder stream) {
        super(host, port);
        this.stream = stream;
    }

    protected void transportClose() throws IOException {
        stream.close();
    }

    protected InputStream getInputStream() throws IOException {
        return stream.getInputStream();
    }

    protected OutputStream getOutputStream() throws IOException {
        return stream.getOutputStream();
    }

    protected void establishConnection(ProxyData proxyData, int connectTimeout) throws IOException {
        // nothing to do, stream is already initialized
        if (stream == null) {
            throw new IOException("Stream can not be null");
        }
    }

    public void setTcpNoDelay(boolean tcpNoDelay) {
        // no control of underlying socket
    }
    
}
