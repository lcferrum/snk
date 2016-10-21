#ifndef VERSION_H
#define VERSION_H

#define _SNK_DEV_VERSION	1
#define _SNK_MAJ_VERSION	2
#define _SNK_MIN_VERSION	1

#define __STRINGIFY(x)		#x
#define _STRINGIFY(x)		__STRINGIFY(x)

#if _SNK_DEV_VERSION!=0
	#define SNK_STR_VERSION _STRINGIFY(_SNK_MAJ_VERSION._SNK_MIN_VERSION) "-dev"
#else
	#define SNK_STR_VERSION _STRINGIFY(_SNK_MAJ_VERSION._SNK_MIN_VERSION)
#endif
#define SNK_VSVI_VERSION	_SNK_MAJ_VERSION,_SNK_MIN_VERSION,0,0

#endif //VERSION_H
