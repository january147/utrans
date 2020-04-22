libutrans = ctypes.CDLL("./libutrans.dll")
libutrans.escape_data.argstype = (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_int8, ctypes.c_int8)
libutrans.escape_data.restype = ctypes.c_int
libutrans.restore_data.argstype = (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_int8, ctypes.c_int8)
libutrans.restore_data.restype = ctypes.c_int