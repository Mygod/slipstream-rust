typedef int _Unwind_Reason_Code;
typedef struct _Unwind_Context _Unwind_Context;
typedef _Unwind_Reason_Code (*_Unwind_Trace_Fn)(_Unwind_Context *, void *);

_Unwind_Reason_Code _Unwind_Backtrace(_Unwind_Trace_Fn trace, void *arg) {
  (void)trace;
  (void)arg;
  return 5;
}

unsigned long _Unwind_GetIP(_Unwind_Context *context) {
  (void)context;
  return 0;
}
