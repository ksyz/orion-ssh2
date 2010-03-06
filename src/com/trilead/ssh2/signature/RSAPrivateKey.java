package com.trilead.ssh2.signature;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * RSAPrivateKey.
 * 
 * @author Christian Plattner, plattner@trilead.com
 * @version $Id: RSAPrivateKey.java,v 1.1 2007/10/15 12:49:57 cplattne Exp $
 */
public class RSAPrivateKey implements Serializable
{
	private BigInteger d;
	private BigInteger e;
	private BigInteger n;

	public RSAPrivateKey() {
	}
	
	public RSAPrivateKey(BigInteger d, BigInteger e, BigInteger n)
	{
		this.d = d;
		this.e = e;
		this.n = n;
	}

	public BigInteger getD()
	{
		return d;
	}
	
	public BigInteger getE()
	{
		return e;
	}

	public BigInteger getN()
	{
		return n;
	}
	
	public RSAPublicKey getPublicKey()
	{
		return new RSAPublicKey(e, n);
	}
}