project('hash', 'c',
  version:          '0.4.1',
  default_options:  ['c_std=c17', 'warning_level=3', 'werror=true'],
  meson_version:    '>=1.3.0',
)

cc = meson.get_compiler('c')
fs = import('fs')
add_project_arguments('-D_DEFAULT_SOURCE', language: 'c')

if get_option('debug')
  add_project_arguments(cc.get_supported_arguments(['-ggdb3']), language: 'c')
endif

add_project_arguments('-Wno-missing-field-initializers', language: 'c')

conf = configuration_data()
conf.set10('TESTMODE', get_option('testmode'))
conf.set10('DEBUG',    get_option('debug'))

add_project_arguments('-DSHA2_USE_INTTYPES_H', language: 'c')
add_project_arguments('-DHAVE_CONFIG_H', language: 'c')

deps = []
inc = []

pkg_sources = files(
  'generic/main.c',
  'generic/md5.c',
  'generic/sha2.c',
  'generic/areion.c',
)

# Hardware acceleration detection
have_aes_ni = false
have_aes_neon = false

if get_option('hardware_accel')
  aes_ni_args = ['-msse4.1', '-maes']
  if cc.compiles('''
    #include <wmmintrin.h>
    int main() {
      __m128i a = _mm_setzero_si128();
      __m128i b = _mm_setzero_si128();
      __m128i c = _mm_aesenc_si128(a, b);
      (void)c;
      return 0;
    }
  ''', args: aes_ni_args)
    have_aes_ni = true
    conf.set10('HAVE_AES_NI', true)
    add_project_arguments(aes_ni_args, language: 'c')
  endif

  if not have_aes_ni
    aes_neon_args = ['-march=armv8-a+crypto']
    if cc.compiles('''
      #include <arm_neon.h>
      int main() {
        uint8x16_t a = vdupq_n_u8(0);
        uint8x16_t b = vdupq_n_u8(0);
        uint8x16_t c = vaeseq_u8(a, b);
        uint8x16_t d = vaesmcq_u8(c);
        (void)d;
        return 0;
      }
    ''', args: aes_neon_args)
      have_aes_neon = true
      conf.set10('HAVE_AES_NEON', true)
      add_project_arguments(aes_neon_args, language: 'c')
    endif
  endif
endif

#subdir('teabase/init')
subdir('teabase')

subdir('doc')
