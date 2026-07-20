<?php
/**
 * MORI 전용 번들 Zabbix 리브랜딩 (Zabbix 6.0+ / 7.x 공식 rebranding).
 *
 * 컨테이너의 /usr/share/zabbix/local/conf/brand.conf.php 로 마운트되면 Zabbix 가
 * 자동 감지해 로고·푸터·도움말 링크를 아래 값으로 교체한다(색 CSS 는 별도 — README 참고).
 * docker-compose 의 zabbix-web volumes 에서 이 파일과 로고 SVG 를 마운트한다.
 *
 * 주의: 재설치(볼륨/이미지 초기화)해도 이 마운트가 유지되면 리브랜딩도 유지된다.
 */
return [
	// 상단/로그인 로고
	'BRAND_LOGO'                 => './local/conf/mori-logo.svg',
	// 사이드바(펼침) 로고
	'BRAND_LOGO_SIDEBAR'         => './local/conf/mori-logo-sidebar.svg',
	// 사이드바(접힘) 컴팩트 로고
	'BRAND_LOGO_SIDEBAR_COMPACT' => './local/conf/mori-logo-compact.svg',
	// 하단 푸터 — MORI 정체성(증적 층)
	'BRAND_FOOTER'               => 'MORI SOC — ISMS-P / ISO 27001 증적 층 · 모니터링은 Zabbix',
	// 도움말 링크를 MORI 문서로
	'BRAND_HELP_URL'             => 'https://github.com/saranf/mori-soc',
];
