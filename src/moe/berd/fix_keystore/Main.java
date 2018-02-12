package moe.berd.fix_keystore;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;

public class Main
{
	public static void main(String[] args)
	{
		if(args.length<5)
		{
			System.out.println("Usage: fixkey <Source> <Output> <Old Alias> <New Alias> <Password>");
		}
		else
		{
			try
			{
				char[] password=args[4].toCharArray();
				JavaKeyStore jks=new JavaKeyStore();
				try(final InputStream is=new FileInputStream(args[0]))
				{
					jks.engineLoad(is,password);
				}
				Key k=jks.engineGetKey(args[2],password);
				Certificate[] certs=jks.engineGetCertificateChain(args[2]);
				KeyStore ks=KeyStore.getInstance("JKS","SUN");
				ks.load(null,null);
				ks.setKeyEntry(args[3],k,password,certs);
				FileOutputStream out=new FileOutputStream(args[1]);
				ks.store(out,password);
				out.close();
			}
			catch(Exception e)
			{
				e.printStackTrace();
			}
		}
	}
}
