import importlib

srv = importlib.import_module('mori_soc.api.server')
i18 = importlib.import_module('mori_soc.api.i18n')

names = ['_LOGIN_I18N', '_SIGNUP_I18N', '_DASHBOARD_I18N', '_ADMIN_I18N']
ok = True
for n in names:
    a = getattr(srv, n)
    b = getattr(i18, n)
    same = (a == b)
    ko = len(a.get('ko', {}))
    en = len(a.get('en', {}))
    print(f'{n:18} equal={same} ko={ko} en={en}')
    if not same:
        ok = False
        ak, bk = set(a.get('ko', {})), set(b.get('ko', {}))
        print('  ko only_srv=', sorted(ak - bk), 'only_i18=', sorted(bk - ak))
        for k in (ak & bk):
            if a['ko'][k] != b['ko'][k]:
                print('  KO VAL', k, repr(a['ko'][k]), '!=', repr(b['ko'][k]))
        ae, be = set(a.get('en', {})), set(b.get('en', {}))
        print('  en only_srv=', sorted(ae - be), 'only_i18=', sorted(be - ae))
        for k in (ae & be):
            if a['en'][k] != b['en'][k]:
                print('  EN VAL', k, repr(a['en'][k]), '!=', repr(b['en'][k]))

print('script equal=', srv._i18n_script(srv._ADMIN_I18N) == i18._i18n_script(i18._ADMIN_I18N))
print('toggle T equal=', srv._i18n_toggle_html(True) == i18._i18n_toggle_html(True))
print('toggle F equal=', srv._i18n_toggle_html(False) == i18._i18n_toggle_html(False))
print('ALL_OK=', ok)
