package moe.berd.fix_keystore;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.DigestInputStream;
import java.security.DigestOutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import sun.misc.IOUtils;
import sun.security.pkcs.EncryptedPrivateKeyInfo;
import sun.security.pkcs12.PKCS12KeyStore;

@SuppressWarnings("Duplicates")
class JavaKeyStore extends KeyStoreSpi
{
	private final Hashtable<String,Object> entries=new Hashtable();
	
	private String convertAlias(String var1)
	{
		return var1;
	}
	
	public Key engineGetKey(String var1,char[] var2) throws NoSuchAlgorithmException, UnrecoverableKeyException
	{
		Object var3=this.entries.get(this.convertAlias(var1));
		if(var3!=null && var3 instanceof KeyEntry)
		{
			if(var2==null)
			{
				throw new UnrecoverableKeyException("Password must not be null");
			}
			else
			{
				KeyProtector var4=new KeyProtector(var2);
				byte[] var5=((KeyEntry)var3).protectedPrivKey;
				
				EncryptedPrivateKeyInfo var6;
				try
				{
					var6=new EncryptedPrivateKeyInfo(var5);
				}
				catch(IOException var9)
				{
					throw new UnrecoverableKeyException("Private key not stored as PKCS #8 EncryptedPrivateKeyInfo");
				}
				
				return var4.recover(var6);
			}
		}
		else
		{
			return null;
		}
	}
	
	public java.security.cert.Certificate[] engineGetCertificateChain(String var1)
	{
		Object var2=this.entries.get(this.convertAlias(var1));
		if(var2!=null && var2 instanceof KeyEntry)
		{
			return ((KeyEntry)var2).chain==null ? null : ((KeyEntry)var2).chain.clone();
		}
		else
		{
			return null;
		}
	}
	
	public java.security.cert.Certificate engineGetCertificate(String var1)
	{
		Object var2=this.entries.get(this.convertAlias(var1));
		if(var2!=null)
		{
			if(var2 instanceof TrustedCertEntry)
			{
				return ((TrustedCertEntry)var2).cert;
			}
			else
			{
				return ((KeyEntry)var2).chain==null ? null : ((KeyEntry)var2).chain[0];
			}
		}
		else
		{
			return null;
		}
	}
	
	public Date engineGetCreationDate(String var1)
	{
		Object var2=this.entries.get(this.convertAlias(var1));
		if(var2!=null)
		{
			return var2 instanceof TrustedCertEntry ? new Date(((TrustedCertEntry)var2).date.getTime()) : new Date(((KeyEntry)var2).date.getTime());
		}
		else
		{
			return null;
		}
	}
	
	public void engineSetKeyEntry(String var1,Key var2,char[] var3,java.security.cert.Certificate[] var4) throws KeyStoreException
	{
		KeyProtector var5;
		if(!(var2 instanceof PrivateKey))
		{
			throw new KeyStoreException("Cannot store non-PrivateKeys");
		}
		else
		{
			try
			{
				synchronized(this.entries)
				{
					KeyEntry var7=new KeyEntry();
					var7.date=new Date();
					var5=new KeyProtector(var3);
					var7.protectedPrivKey=var5.protect(var2);
					if(var4!=null && var4.length!=0)
					{
						var7.chain=var4.clone();
					}
					else
					{
						var7.chain=null;
					}
					
					this.entries.put(this.convertAlias(var1),var7);
				}
			}
			catch(NoSuchAlgorithmException var14)
			{
				throw new KeyStoreException("Key protection algorithm not found");
			}
		}
	}
	
	public void engineSetKeyEntry(String var1,byte[] var2,java.security.cert.Certificate[] var3) throws KeyStoreException
	{
		synchronized(this.entries)
		{
			try
			{
				new EncryptedPrivateKeyInfo(var2);
			}
			catch(IOException var7)
			{
				throw new KeyStoreException("key is not encoded as EncryptedPrivateKeyInfo");
			}
			
			KeyEntry var5=new KeyEntry();
			var5.date=new Date();
			var5.protectedPrivKey=var2.clone();
			if(var3!=null && var3.length!=0)
			{
				var5.chain=var3.clone();
			}
			else
			{
				var5.chain=null;
			}
			
			this.entries.put(this.convertAlias(var1),var5);
		}
	}
	
	public void engineSetCertificateEntry(String var1,java.security.cert.Certificate var2) throws KeyStoreException
	{
		synchronized(this.entries)
		{
			Object var4=this.entries.get(this.convertAlias(var1));
			if(var4!=null && var4 instanceof KeyEntry)
			{
				throw new KeyStoreException("Cannot overwrite own certificate");
			}
			else
			{
				TrustedCertEntry var5=new TrustedCertEntry();
				var5.cert=var2;
				var5.date=new Date();
				this.entries.put(this.convertAlias(var1),var5);
			}
		}
	}
	
	public void engineDeleteEntry(String var1)
	{
		synchronized(this.entries)
		{
			this.entries.remove(this.convertAlias(var1));
		}
	}
	
	public Enumeration<String> engineAliases()
	{
		return this.entries.keys();
	}
	
	public boolean engineContainsAlias(String var1)
	{
		return this.entries.containsKey(this.convertAlias(var1));
	}
	
	public int engineSize()
	{
		return this.entries.size();
	}
	
	public boolean engineIsKeyEntry(String var1)
	{
		Object var2=this.entries.get(this.convertAlias(var1));
		return var2!=null && var2 instanceof KeyEntry;
	}
	
	public boolean engineIsCertificateEntry(String var1)
	{
		Object var2=this.entries.get(this.convertAlias(var1));
		return var2!=null && var2 instanceof TrustedCertEntry;
	}
	
	public String engineGetCertificateAlias(java.security.cert.Certificate var1)
	{
		Enumeration var3=this.entries.keys();
		
		java.security.cert.Certificate var2;
		String var4;
	label24:
		do
		{
			Object var5;
			do
			{
				if(!var3.hasMoreElements())
				{
					return null;
				}
				
				var4=(String)var3.nextElement();
				var5=this.entries.get(var4);
				if(var5 instanceof TrustedCertEntry)
				{
					var2=((TrustedCertEntry)var5).cert;
					continue label24;
				}
			}while(((KeyEntry)var5).chain==null);
			
			var2=((KeyEntry)var5).chain[0];
		}while(!var2.equals(var1));
		
		return var4;
	}
	
	@SuppressWarnings("LoopStatementThatDoesntLoop")
	public void engineStore(OutputStream var1,char[] var2) throws IOException, NoSuchAlgorithmException, CertificateException
	{
		synchronized(this.entries)
		{
			if(var2==null)
			{
				throw new IllegalArgumentException("password can't be null");
			}
			else
			{
				MessageDigest var5=this.getPreKeyedHash(var2);
				DataOutputStream var6=new DataOutputStream(new DigestOutputStream(var1,var5));
				var6.writeInt(-17957139);
				var6.writeInt(2);
				var6.writeInt(this.entries.size());
				Enumeration var7=this.entries.keys();
				while(true)
				{
					while(var7.hasMoreElements())
					{
						String var8=(String)var7.nextElement();
						Object var9=this.entries.get(var8);
						byte[] var4;
						if(var9 instanceof KeyEntry)
						{
							var6.writeInt(1);
							var6.writeUTF(var8);
							var6.writeLong(((KeyEntry)var9).date.getTime());
							var6.writeInt(((KeyEntry)var9).protectedPrivKey.length);
							var6.write(((KeyEntry)var9).protectedPrivKey);
							int var10;
							if(((KeyEntry)var9).chain==null)
							{
								var10=0;
							}
							else
							{
								var10=((KeyEntry)var9).chain.length;
							}
							
							var6.writeInt(var10);
							
							for(int var11=0;var11<var10;++var11)
							{
								var4=((KeyEntry)var9).chain[var11].getEncoded();
								var6.writeUTF(((KeyEntry)var9).chain[var11].getType());
								var6.writeInt(var4.length);
								var6.write(var4);
							}
						}
						else
						{
							var6.writeInt(2);
							var6.writeUTF(var8);
							var6.writeLong(((TrustedCertEntry)var9).date.getTime());
							var4=((TrustedCertEntry)var9).cert.getEncoded();
							var6.writeUTF(((TrustedCertEntry)var9).cert.getType());
							var6.writeInt(var4.length);
							var6.write(var4);
						}
					}
					byte[] var14=var5.digest();
					var6.write(var14);
					var6.flush();
					return;
				}
			}
		}
	}
	
	public void engineLoad(InputStream var1,char[] var2) throws IOException, NoSuchAlgorithmException, CertificateException
	{
		synchronized(this.entries)
		{
			MessageDigest var5=null;
			CertificateFactory var6=null;
			Hashtable var7=null;
			ByteArrayInputStream var8;
			if(var1!=null)
			{
				DataInputStream var4;
				if(var2!=null)
				{
					var5=this.getPreKeyedHash(var2);
					var4=new DataInputStream(new DigestInputStream(var1,var5));
				}
				else
				{
					var4=new DataInputStream(var1);
				}
				
				int var10=var4.readInt();
				int var11=var4.readInt();
				if(var10==-17957139 && (var11==1 || var11==2))
				{
					if(var11==1)
					{
						var6=CertificateFactory.getInstance("X509");
					}
					else
					{
						var7=new Hashtable(3);
					}
					
					this.entries.clear();
					int var12=var4.readInt();
					
					for(int var13=0;var13<var12;++var13)
					{
						int var14=var4.readInt();
						String var15;
						byte[] var23;
						if(var14!=1)
						{
							if(var14!=2)
							{
								throw new IOException("Unrecognized keystore entry");
							}
							
							TrustedCertEntry var27=new TrustedCertEntry();
							var15=var4.readUTF();
							var27.date=new Date(var4.readLong());
							if(var11==2)
							{
								String var29=var4.readUTF();
								if(var7.containsKey(var29))
								{
									var6=(CertificateFactory)var7.get(var29);
								}
								else
								{
									var6=CertificateFactory.getInstance(var29);
									var7.put(var29,var6);
								}
							}
							
							var23=IOUtils.readFully(var4,var4.readInt(),true);
							var8=new ByteArrayInputStream(var23);
							var27.cert=var6.generateCertificate(var8);
							var8.close();
							this.entries.put(var15,var27);
						}
						else
						{
							KeyEntry var16=new KeyEntry();
							var15=var4.readUTF();
							var16.date=new Date(var4.readLong());
							var16.protectedPrivKey=IOUtils.readFully(var4,var4.readInt(),true);
							int var17=var4.readInt();
							if(var17>0)
							{
								ArrayList var18=new ArrayList(var17>10 ? 10 : var17);
								
								for(int var19=0;var19<var17;++var19)
								{
									if(var11==2)
									{
										String var20=var4.readUTF();
										if(var7.containsKey(var20))
										{
											var6=(CertificateFactory)var7.get(var20);
										}
										else
										{
											var6=CertificateFactory.getInstance(var20);
											var7.put(var20,var6);
										}
									}
									
									var23=IOUtils.readFully(var4,var4.readInt(),true);
									var8=new ByteArrayInputStream(var23);
									var18.add(var6.generateCertificate(var8));
									var8.close();
								}
								
								var16.chain=(java.security.cert.Certificate[])var18.toArray(new java.security.cert.Certificate[var17]);
							}
							
							this.entries.put(var15,var16);
						}
					}
					
					if(var2!=null)
					{
						byte[] var24=var5.digest();
						byte[] var25=new byte[var24.length];
						var4.readFully(var25);
						
						for(int var26=0;var26<var24.length;++var26)
						{
							if(var24[var26]!=var25[var26])
							{
								UnrecoverableKeyException var28=new UnrecoverableKeyException("Password verification failed");
								throw new IOException("Keystore was tampered with, or password was incorrect",var28);
							}
						}
					}
					
				}
				else
				{
					throw new IOException("Invalid keystore format");
				}
			}
		}
	}
	
	private MessageDigest getPreKeyedHash(char[] var1) throws NoSuchAlgorithmException, UnsupportedEncodingException
	{
		MessageDigest var4=MessageDigest.getInstance("SHA");
		byte[] var5=new byte[var1.length*2];
		int var2=0;
		
		for(int var3=0;var2<var1.length;++var2)
		{
			var5[var3++]=(byte)(var1[var2] >> 8);
			var5[var3++]=(byte)var1[var2];
		}
		
		var4.update(var5);
		
		for(var2=0;var2<var5.length;++var2)
		{
			var5[var2]=0;
		}
		
		var4.update("Mighty Aphrodite".getBytes("UTF8"));
		return var4;
	}
	
	private static class KeyEntry
	{
		Date date;
		byte[] protectedPrivKey;
		java.security.cert.Certificate[] chain;
		
		private KeyEntry()
		{
		}
	}
	
	private static class TrustedCertEntry
	{
		Date date;
		java.security.cert.Certificate cert;
		
		private TrustedCertEntry()
		{
		}
	}
}
