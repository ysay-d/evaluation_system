var satelliteImageCode = "GS京(2023)0751号";
var amapCommonConfig = {
	mapCode: "GS(2021)6375号",
	jiace: "甲测资字11111093",
	amapBeian: "<a href='https://beian.miit.gov.cn' target='_blank'>京ICP备07017245号-2</a>",
	gaodeBeian: "<a href='https://beian.miit.gov.cn' target='_blank'>京ICP备07017245号-7</a>",
	anbei: " - <span><a target='_blank' style='color:#565656' href='http://www.beian.gov.cn/portal/registerSystemInfo?recordcode=11010502030880'><img style='margin-bottom:1px' src='assets/image/beian.png' />京公网安备 11010502030880号</a></span>",
	jubao: "",
	satelliteCode: satelliteImageCode + " - Image© DigitalGlobe＆spaceview",
  	dianxinxuke: "<a href='https://cache.gaode.com/activity/lowcode/h5/qzKxxus1/index.html' target='_blank'>增值电信业务经营许可证</a>",
	zhizhao: "<a href='https://zzlz.gsxt.gov.cn/businessCheck/verifKey.do?showType=p&serial=911101147263767522-SAIC_SHOW_1000009111011472637675221634549375904&signData=MEYCIQC6YhrawPfPQ8XfjPY8fN5wNdu8l+KqdSItU2DkYJ/JFwIhANcn/1OtIQWvr1tXIV8oTPoiUNj32JVBn4bpDsXhNZ8d' target='_blank'><img src='assets/image/lz4.png'></a>",
  links: [{
    title: "资质证照",
    url: "https://a.amap.com/pc/static/page/info.html",
    trace: "zizhi"
  },{
    title: "协议与声明",
    url: "https://map.amap.com/doc/serviceitem.html",
    trace: "tos"
  },{
    title: "开放平台",
    url: "https://lbs.amap.com/",
    trace: "lbs"
  },{
    title: "新增地点",
    url: "https://map.amap.com/help/index.html?type=addpoi",
    trace: "addpoi"
  },{
    title: "意见反馈",
    url: "https://map.amap.com/help/index.html",
    trace: "feedback"
  },{
    title: "商户免费标注",
    url: "http://bgc.amap.com?src=pcbottom",
    trace: "addtag"
  },{
    title: "车机版",
    url: "https://www.amapauto.com?src=pc_openapi",
    trace: "auto"
  },{
    title: "网上有害信息举报",
    url: "https://www.12377.cn/",
    trace: "tipoff"
  },{
    title: "涉未成年人举报",
    url: "https://a.amap.com/pc/static/page/report.html",
    trace: "tipoff_wcn"
  },{
    title: "算法推荐举报",
    url: "https://a.amap.com/pc/static/page/report.html",
    trace: "tipoff_sftj"
  },{
    title: "生活服务专项举报",
    url: "https://a.amap.com/pc/static/page/report.html",
    trace: "tipoff_shfwzx"
  },{
    title: "廉正举报",
    url: "https://a.amap.com/pc/static/page/report.html",
    trace: "tipoff_lz"
  }]
}

var zzlist = [{
	title: "地图审图号",
	val: amapCommonConfig.mapCode
},{
	title: "卫星图片审图号",
	val: satelliteImageCode
},{
	title: "测绘资质证号",
	val: amapCommonConfig.jiace
},{
	title: "",
	val: amapCommonConfig.dianxinxuke
},{
	title: "ICP备案号",
	val: amapCommonConfig.amapBeian
},{
	title: "营业执照",
	val: amapCommonConfig.zhizhao
}]

var reportList = [{
  title: "网上有害信息举报专区",
  val: "<a href='https://www.12377.cn/' target='_blank'>举报入口</a>"
},{
  title: "涉未成年人举报邮箱",
  val: "举报邮箱：gd.wcn.jubao@service.autonavi.com"
},{
  title: "算法推荐举报邮箱",
  val: "举报邮箱：gd.sftj.jubao@service.autonavi.com"
},{
  title: "生活服务专项举报邮箱",
  val: "举报邮箱：gd.shfw.jubao@service.autonavi.com"
},{
  title: "高德地图廉正举报",
  val: "<a href='https://gaode.jubao.alibaba.com' target='_blank'>举报系统入口</a></br>举报邮箱：integrity-amap@alibaba-inc.com</br><span style='font-size: 13px;color: #000;opacity: 0.5;'>以上联络方法只适用于涉及高德地图员工诚信问题的咨询或举报</span>"
}]