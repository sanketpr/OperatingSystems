typedef int32_t fixed_point;

#define Q 14
#define P 17
#define F 1 << (Q)

#define ADD_FIXED_POINT(x, y) (x) + (y)
#define SUB_FIXED_POINT(x, y) (x) - (y)
#define MUL_FIXED_POINT(x, y) ((int64_t)(x)) * (y) / (F)
#define DIV_FIXED_POINT(x, y) ((int64_t)(x)) * (F) / (y)

#define ADD_INT_FIXED_POINT(x, n) (x) + (n) * (F)
#define SUB_INT_FIXED_POINT(x, n) (x) - (n) * (F)
#define MUL_INT_FIXED_POINT(x, n) (x) * (n)
#define DIV_INT_FIXED_POINT(x, n) (x) / (n)

#define CONVERT_N_TO_FIXED_POINT(n) (n) * (F)
#define CONVERT_X_TO_INTEGER(x) ((x) >= 0 ? ((x) + (F) / 2)\
                                   / (F) : ((x) - (F) / 2)\
                                   / (F))
