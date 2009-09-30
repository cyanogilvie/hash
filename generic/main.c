#include <tclstuff.h>
#include "md5.h"

static int glue_md5(cdata, interp, objc, objv) //<<<
	ClientData		cdata;
	Tcl_Interp*		interp;
	int				objc;
	Tcl_Obj *const	objv[];
{
	md5_byte_t*		bytes;
	int				len;
	md5_byte_t		digest[16];
	md5_state_t		state;

	CHECK_ARGS(1, "data");

	bytes = (md5_byte_t*)Tcl_GetByteArrayFromObj(objv[1], &len);

	md5_init(&state);
	md5_append(&state, bytes, len);
	md5_finish(&state, digest);

	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(digest, 16));

	return TCL_OK;
}

//>>>
int Hash_Init(Tcl_Interp* interp) //<<<
{
	if (Tcl_InitStubs(interp, "8.4", 0) == NULL)
		return TCL_ERROR;

	NEW_CMD(PACKAGE_NAME "::md5", glue_md5);

	TEST_OK(Tcl_PkgProvide(interp, PACKAGE_NAME, PACKAGE_VERSION));

	return TCL_OK;
}

//>>>

// vim: foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
