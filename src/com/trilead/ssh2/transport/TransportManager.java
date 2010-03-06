
package com.trilead.ssh2.transport;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.Vector;
import java.security.SecureRandom;

import com.trilead.ssh2.crypto.Base64;
import com.trilead.ssh2.crypto.CryptoWishList;
import com.trilead.ssh2.crypto.cipher.BlockCipher;
import com.trilead.ssh2.crypto.digest.MAC;
import com.trilead.ssh2.log.Logger;
import com.trilead.ssh2.packets.PacketDisconnect;
import com.trilead.ssh2.packets.Packets;
import com.trilead.ssh2.packets.TypesReader;
import com.trilead.ssh2.util.Tokenizer;
import com.trilead.ssh2.ConnectionInfo;
import com.trilead.ssh2.ConnectionMonitor;
import com.trilead.ssh2.DHGexParameters;
import com.trilead.ssh2.HTTPProxyData;
import com.trilead.ssh2.HTTPProxyException;
import com.trilead.ssh2.ProxyData;
import com.trilead.ssh2.ServerHostKeyVerifier;



/*
 * Yes, the "standard" is a big mess. On one side, the say that arbitary channel
 * packets are allowed during kex exchange, on the other side we need to blindly
 * ignore the next _packet_ if the KEX guess was wrong. Where do we know from that
 * the next packet is not a channel data packet? Yes, we could check if it is in
 * the KEX range. But the standard says nothing about this. The OpenSSH guys
 * block local "normal" traffic during KEX. That's fine - however, they assume
 * that the other side is doing the same. During re-key, if they receive traffic
 * other than KEX, they become horribly irritated and kill the connection. Since
 * we are very likely going to communicate with OpenSSH servers, we have to play
 * the same game - even though we could do better.
 * 
 * btw: having stdout and stderr on the same channel, with a shared window, is
 * also a VERY good idea... =(
 */

/**
 * TransportManager.
 * 
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: TransportManager.java,v 1.2 2008/04/01 12:38:09 cplattne Exp $
 */
public class TransportManager extends GenericTransportManager
{
	final Socket sock = new Socket();

	/**
	 * There were reports that there are JDKs which use
	 * the resolver even though one supplies a dotted IP
	 * address in the Socket constructor. That is why we
	 * try to generate the InetAdress "by hand".
	 * 
	 * @param host
	 * @return the InetAddress
	 * @throws UnknownHostException
	 */
	static InetAddress createInetAddress(String host) throws UnknownHostException
	{
		/* Check if it is a dotted IP4 address */

		InetAddress addr = parseIPv4Address(host);

		if (addr != null)
			return addr;

		return InetAddress.getByName(host);
	}

	private static InetAddress parseIPv4Address(String host) throws UnknownHostException
	{
		if (host == null)
			return null;

		String[] quad = Tokenizer.parseTokens(host, '.');

		if ((quad == null) || (quad.length != 4))
			return null;

		byte[] addr = new byte[4];

		for (int i = 0; i < 4; i++)
		{
			int part = 0;

			if ((quad[i].length() == 0) || (quad[i].length() > 3))
				return null;

			for (int k = 0; k < quad[i].length(); k++)
			{
				char c = quad[i].charAt(k);

				/* No, Character.isDigit is not the same */
				if ((c < '0') || (c > '9'))
					return null;

				part = part * 10 + (c - '0');
			}

			if (part > 255) /* 300.1.2.3 is invalid =) */
				return null;

			addr[i] = (byte) part;
		}

		return InetAddress.getByAddress(host, addr);
	}

	public TransportManager(String host, int port) throws IOException
	{
		super(host, port);
	}

	public void setTcpNoDelay(boolean state) throws IOException
	{
		sock.setTcpNoDelay(state);
	}

	public void setSoTimeout(int timeout) throws IOException
	{
		sock.setSoTimeout(timeout);
	}

        protected void transportClose() throws IOException 
	{
            sock.close();
        }
	
	protected void establishConnection(ProxyData proxyData, int connectTimeout) throws IOException
	{
		/* See the comment for createInetAddress() */

		if (proxyData == null)
		{
			InetAddress addr = createInetAddress(hostname);
			sock.connect(new InetSocketAddress(addr, port), connectTimeout);
			sock.setSoTimeout(0);
			return;
		}

		if (proxyData instanceof HTTPProxyData)
		{
			HTTPProxyData pd = (HTTPProxyData) proxyData;

			/* At the moment, we only support HTTP proxies */

			InetAddress addr = createInetAddress(pd.proxyHost);
			sock.connect(new InetSocketAddress(addr, pd.proxyPort), connectTimeout);
			sock.setSoTimeout(0);

			/* OK, now tell the proxy where we actually want to connect to */

			StringBuffer sb = new StringBuffer();

			sb.append("CONNECT ");
			sb.append(hostname);
			sb.append(':');
			sb.append(port);
			sb.append(" HTTP/1.0\r\n");

			if ((pd.proxyUser != null) && (pd.proxyPass != null))
			{
				String credentials = pd.proxyUser + ":" + pd.proxyPass;
				char[] encoded = Base64.encode(credentials.getBytes("ISO-8859-1"));
				sb.append("Proxy-Authorization: Basic ");
				sb.append(encoded);
				sb.append("\r\n");
			}

			if (pd.requestHeaderLines != null)
			{
				for (int i = 0; i < pd.requestHeaderLines.length; i++)
				{
					if (pd.requestHeaderLines[i] != null)
					{
						sb.append(pd.requestHeaderLines[i]);
						sb.append("\r\n");
					}
				}
			}

			sb.append("\r\n");

			OutputStream out = sock.getOutputStream();

			out.write(sb.toString().getBytes("ISO-8859-1"));
			out.flush();

			/* Now parse the HTTP response */

			byte[] buffer = new byte[1024];
			InputStream in = sock.getInputStream();

			int len = ClientServerHello.readLineRN(in, buffer);

			String httpReponse = new String(buffer, 0, len, "ISO-8859-1");

			if (httpReponse.startsWith("HTTP/") == false)
				throw new IOException("The proxy did not send back a valid HTTP response.");

			/* "HTTP/1.X XYZ X" => 14 characters minimum */

			if ((httpReponse.length() < 14) || (httpReponse.charAt(8) != ' ') || (httpReponse.charAt(12) != ' '))
				throw new IOException("The proxy did not send back a valid HTTP response.");

			int errorCode = 0;

			try
			{
				errorCode = Integer.parseInt(httpReponse.substring(9, 12));
			}
			catch (NumberFormatException ignore)
			{
				throw new IOException("The proxy did not send back a valid HTTP response.");
			}

			if ((errorCode < 0) || (errorCode > 999))
				throw new IOException("The proxy did not send back a valid HTTP response.");

			if (errorCode != 200)
			{
				throw new HTTPProxyException(httpReponse.substring(13), errorCode);
			}

			/* OK, read until empty line */

			while (true)
			{
				len = ClientServerHello.readLineRN(in, buffer);
				if (len == 0)
					break;
			}
			return;
		}

		throw new IOException("Unsupported ProxyData");
	}


        protected InputStream getInputStream() throws IOException {
            return sock.getInputStream();
        }
        
        protected OutputStream getOutputStream() throws IOException {
            return sock.getOutputStream();
        }
}
