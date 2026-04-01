AC_DEFUN([AM_ICONV], [
  AC_ARG_WITH([libiconv-prefix],
    [AS_HELP_STRING([--with-libiconv-prefix=DIR], [search for libiconv in DIR/include and DIR/lib])], [
    for dir in `echo "$withval" | tr : ' '`; do
      if test -d "$dir/include"; then CPPFLAGS="$CPPFLAGS -I$dir/include"; fi
      if test -d "$dir/lib"; then LDFLAGS="$LDFLAGS -L$dir/lib"; fi
    done
   ])

  AC_CACHE_CHECK([for iconv], [am_cv_func_iconv], [
    am_cv_func_iconv="no, consider installing GNU libiconv"
    am_cv_lib_iconv=no
    AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <stdlib.h>
#include <iconv.h>], [iconv_t cd = iconv_open("","");
       iconv(cd,NULL,NULL,NULL,NULL);
       iconv_close(cd);])],
      [am_cv_func_iconv=yes])
    if test "$am_cv_func_iconv" != yes; then
      am_save_LIBS="$LIBS"
      LIBS="$LIBS -liconv"
      AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <stdlib.h>
#include <iconv.h>], [iconv_t cd = iconv_open("","");
         iconv(cd,NULL,NULL,NULL,NULL);
         iconv_close(cd);])],
        [am_cv_lib_iconv=yes
         am_cv_func_iconv=yes])
      LIBS="$am_save_LIBS"
    fi
  ])
  if test "$am_cv_func_iconv" = yes; then
    AC_DEFINE([HAVE_ICONV], [1], [Define if you have the iconv() function.])
    if test "$am_cv_lib_iconv" = yes; then
      LIBICONV="-liconv"
      LTLIBICONV="-liconv"
    else
      LIBICONV=""
      LTLIBICONV=""
    fi
    AC_SUBST([LIBICONV])
    AC_SUBST([LTLIBICONV])
  fi
])
