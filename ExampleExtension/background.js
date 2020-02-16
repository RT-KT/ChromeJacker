
chrome.tabs.onUpdated.addListener(function(tabid, changeinfo, tab) {
    var url = tab.url;
        if (url !== undefined && changeinfo.status == "complete") {

        chrome.tabs.executeScript(null, {
		file: 'inject.js'
	});
	
    }
   });
