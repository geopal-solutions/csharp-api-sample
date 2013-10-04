using System;
using System.Text;
using System.Security.Cryptography;
using System.Collections.Specialized;
using System.Collections.Generic;
using System.Net;
using System.IO;

namespace GeopalJobSample
{
	public class GeopalClient
	{
		private const String DEFAULT_PRIVATEKEY = "";
		private const String DEFAULT_EMPLOYEEID = "";
		private const String GEOPAL_BASE_URL = "https://app.geopalsolutions.com/";

		private const String HEADER_GEOPAL_SIGNATURE = "GEOPAL_SIGNATURE";
		private const String HEADER_GEOPAL_TIMESTAMP = "GEOPAL_TIMESTAMP";
		private const String HEADER_GEOPAL_EMPLOYEEID = "GEOPAL_EMPLOYEEID";

		private String uri = "";
		private String employeeId = DEFAULT_EMPLOYEEID;
		private String privateKey = DEFAULT_PRIVATEKEY;

		public GeopalClient ()
		{
		}

		public GeopalClient (String uri)
		{
			setUri(uri);
		}


		public string post(NameValueCollection pairs) 
		{
			WebClient wb = generateWebClient("POST", this.uri);
			return Encoding.ASCII.GetString(wb.UploadValues(getUrl(), "POST", pairs));
		}

		public string post(string file, string contentType, string jobTemplateFieldId, NameValueCollection nvc) {
			string content = "";
			Dictionary<string, string> dictionary = getHeadersDictionary("POST", this.uri);

			string boundary = "---------------------------" + DateTime.Now.Ticks.ToString("x");
			byte[] boundarybytes = System.Text.Encoding.ASCII.GetBytes("\r\n--" + boundary + "\r\n");
			
			HttpWebRequest wr = (HttpWebRequest)WebRequest.Create(getUrl());
			wr.ContentType = "multipart/form-data; boundary=" + boundary;
			wr.Method = "POST";
			wr.KeepAlive = true;
			wr.Credentials = System.Net.CredentialCache.DefaultCredentials;
			wr.Headers.Add(HEADER_GEOPAL_SIGNATURE, dictionary[HEADER_GEOPAL_SIGNATURE]);
			wr.Headers.Add(HEADER_GEOPAL_EMPLOYEEID, dictionary[HEADER_GEOPAL_EMPLOYEEID]);
			wr.Headers.Add(HEADER_GEOPAL_TIMESTAMP, dictionary[HEADER_GEOPAL_TIMESTAMP]);
			Stream rs = wr.GetRequestStream();
			
			string formdataTemplate = "Content-Disposition: form-data; name=\"{0}\"\r\n\r\n{1}";
			foreach (string key in nvc.Keys)
			{
				rs.Write(boundarybytes, 0, boundarybytes.Length);
				string formitem = string.Format(formdataTemplate, key, nvc[key]);
				byte[] formitembytes = System.Text.Encoding.UTF8.GetBytes(formitem);
				rs.Write(formitembytes, 0, formitembytes.Length);
			}
			rs.Write(boundarybytes, 0, boundarybytes.Length);



			string headerTemplate = "Content-Disposition: form-data; name=\"{0}\"; filename=\"{1}\"\r\nContent-Type: {2}\r\n\r\n";
			string header = string.Format(headerTemplate, jobTemplateFieldId, file, contentType);
			byte[] headerbytes = System.Text.Encoding.UTF8.GetBytes(header);
			rs.Write(headerbytes, 0, headerbytes.Length);
			
			FileStream fileStream = new FileStream(file, FileMode.Open, FileAccess.Read);
			byte[] buffer = new byte[4096];
			int bytesRead = 0;
			while ((bytesRead = fileStream.Read(buffer, 0, buffer.Length)) != 0) {
				rs.Write(buffer, 0, bytesRead);
			}
			fileStream.Close();
			
			byte[] trailer = System.Text.Encoding.ASCII.GetBytes("\r\n--" + boundary + "--\r\n");
			rs.Write(trailer, 0, trailer.Length);
			rs.Close();
			
			WebResponse wresp = null;
			try {
				wresp = wr.GetResponse();
				Stream stream2 = wresp.GetResponseStream();
				using(StreamReader reader = new StreamReader(stream2, Encoding.ASCII))
				{
					content = reader.ReadToEnd();
				}
			} catch(Exception ex) {
				if(wresp != null) {
					wresp.Close();
					wresp = null;
				}
			} finally {
				wr = null;
			}
			return content;
		}
		
		public string put(NameValueCollection pairs)
		{
			WebClient wb = generateWebClient("PUT", this.uri);
			return Encoding.ASCII.GetString(wb.UploadValues(getUrl(), "PUT", pairs));
		}

		public string get(String urlPairs)
		{
			WebClient wb = generateWebClient("GET", this.uri);
			return wb.DownloadString(getUrl()+"?"+urlPairs);
		}

		public string get ()
		{
			WebClient wb = generateWebClient ("GET", this.uri);
			return wb.DownloadString (getUrl ());
		}

		public void downloadFile(String urlPairs, string fileLocation)
		{
			WebClient wb = generateWebClient("GET", this.uri);
			wb.DownloadFile(getUrl()+"?"+urlPairs, fileLocation);
		}

		public void setUri (String uri)
		{
			this.uri = uri;
		}

		public void setEmployeeId (string employeeId)
		{
			this.employeeId = employeeId;
		}

		public void setPrivateKey (string privatekey)
		{
			this.privateKey = privatekey;
		}

		private String getUrl ()
		{
			return GEOPAL_BASE_URL + this.uri;
		}


		private WebClient generateWebClient(String method, String uri)
		{
			Dictionary<string, string> dictionary = getHeadersDictionary(method, uri);
			WebClient wb = new WebClient();
			WebHeaderCollection wbHeaders = new WebHeaderCollection();
			wbHeaders.Add(HEADER_GEOPAL_SIGNATURE, dictionary[HEADER_GEOPAL_SIGNATURE]);
			wbHeaders.Add(HEADER_GEOPAL_TIMESTAMP, dictionary[HEADER_GEOPAL_TIMESTAMP]);
			wbHeaders.Add(HEADER_GEOPAL_EMPLOYEEID, dictionary[HEADER_GEOPAL_EMPLOYEEID]);
			wb.Headers = wbHeaders;
			return wb;
		}


		public Dictionary<string, string> getHeadersDictionary(String method, String uri)
		{
			method = method.ToLower();
			DateTime now = DateTime.Now;
			String timestamp = now.ToString("ddd, dd MMM yyyy hh:mm:ss ")+"GMT";
			string signature = GetSignature(method + uri + employeeId + timestamp, privateKey);
			Dictionary<string, string> dictionary = new Dictionary<string, string>();
			dictionary.Add(HEADER_GEOPAL_SIGNATURE, signature);
			dictionary.Add(HEADER_GEOPAL_TIMESTAMP, timestamp);
			dictionary.Add(HEADER_GEOPAL_EMPLOYEEID, employeeId);
			return dictionary;
		}

		private string GetSignature(string signtext, string privateKey)
		{
			System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
			
			byte[] keybytes = encoding.GetBytes(privateKey);
			byte[] signbytes = encoding.GetBytes(signtext);
			
			HMACSHA256 hmacsha256 = new HMACSHA256(keybytes);
			
			return EncodeTo64(ByteToString(hmacsha256.ComputeHash(signbytes)).ToLower());
		}
		
		private string EncodeTo64(string toEncode)
		{
			byte[] toEncodeAsBytes
				= System.Text.ASCIIEncoding.ASCII.GetBytes(toEncode);
			string returnValue
				= System.Convert.ToBase64String(toEncodeAsBytes);
			return returnValue;
		}
		
		private static string ByteToString(byte[] buff)
		{
			string sbinary = "";
			
			for (int i = 0; i < buff.Length; i++)
			{
				sbinary += buff[i].ToString("X2"); // hex format
			}
			return (sbinary);
		}
	}
}

