/*
 * StreamConnection.java
 *
 * Created on April 14, 2007, 8:55 PM
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */

package com.trilead.ssh2;

import com.trilead.ssh2.transport.GenericTransportManager;
import com.trilead.ssh2.transport.StreamTransportManager;
import java.io.IOException;

/**
 *
 * @author juraj
 */
public class StreamConnection extends Connection {
    
    private LocalStreamForwarder stream = null;
    
    public StreamConnection(String hostname, int port) {
        super(hostname, port);
    }
    
    
    public StreamConnection(String hostname, int port, LocalStreamForwarder stream) {
        super(hostname, port);
        this.stream = stream;
    }
    
    public StreamConnection(String hostname, int port, Connection connection) throws IOException {
        super(hostname, port);
        this.stream = connection.createLocalStreamForwarder(hostname, port);
    }
    
    
    protected GenericTransportManager createTransportManager() throws IOException{
        return new StreamTransportManager(getHostname(), getPort(), stream);
    }
    
}
