<?php declare(strict_types = 0);
/**
 * DDoS Guard - SOC Overview - view
 * @var CView $this
 * @var array $data
 */
$kpis   = $data['kpis'];
$alerts = $data['alerts'];
$hosts  = $data['hosts'];
$sc = ['critical'=>'#d63939','high'=>'#f0a30a','medium'=>'#4b8cb8','low'=>'#2fa84f','info'=>'#999'];

$style = (new CTag('style', true))->addItem('
	.dgsoc { display: flex; flex-direction: column; gap: 8px; }
	.dgsoc-kpis { display: flex; gap: 6px; flex-wrap: wrap; }
	.dgsoc-kpi { flex: 1; min-width: 90px; background: rgba(128,128,128,.07);
		border-radius: 4px; padding: 8px 10px; border-top: 2px solid #ccc; }
	.dgsoc-kpi-label { font-size: 9px; text-transform: uppercase; color: #999;
		margin-bottom: 3px; letter-spacing: .06em; }
	.dgsoc-kpi-value { font-size: 22px; font-weight: 700; line-height: 1; }
	.dgsoc-kpi-sub { font-size: 10px; color: #999; margin-top: 2px; }
	.dgsoc-tl { background: rgba(128,128,128,.05); border: 1px solid rgba(128,128,128,.12);
		border-radius: 4px; padding: 8px 12px; }
	.dgsoc-tl-title { font-size: 10px; font-weight: 700; margin-bottom: 8px; }
	.dgsoc-tl-track { display: flex; align-items: flex-start; }
	.dgsoc-tl-step { flex: 1; display: flex; flex-direction: column; align-items: center; position: relative; }
	.dgsoc-tl-step:not(:last-child)::after { content: ""; position: absolute;
		top: 10px; left: 50%; width: 100%; height: 2px; background: rgba(128,128,128,.2); z-index: 0; }
	.dgsoc-tl-step.done:not(:last-child)::after { background: #2fa84f; }
	.dgsoc-tl-circle { width: 20px; height: 20px; border-radius: 50%;
		display: flex; align-items: center; justify-content: center;
		font-size: 9px; font-weight: 700; z-index: 1;
		border: 2px solid #ccc; background: #fff; color: #999; }
	.dgsoc-tl-step.done .dgsoc-tl-circle { border-color: #2fa84f; background: #e8f5e9; color: #2fa84f; }
	.dgsoc-tl-step.act  .dgsoc-tl-circle { border-color: #f0a30a; background: #fff8e1; color: #f0a30a; }
	.dgsoc-tl-name { font-size: 8px; color: #999; margin-top: 3px; text-align: center; line-height: 1.2; }
	.dgsoc-tl-time { font-size: 9px; font-weight: 700; font-family: monospace; }
	.dgsoc-tl-metrics { display: flex; gap: 12px; padding-top: 6px;
		border-top: 1px solid rgba(128,128,128,.1); margin-top: 6px; }
	.dgsoc-tl-m { display: flex; flex-direction: column; gap: 1px; }
	.dgsoc-tl-mv { font-size: 13px; font-weight: 700; font-family: monospace; }
	.dgsoc-tl-mk { font-size: 8px; color: #999; text-transform: uppercase; letter-spacing: .06em; }
	.dgsoc-bottom { display: flex; gap: 8px; }
	.dgsoc-alerts, .dgsoc-hosts { flex: 1; background: rgba(128,128,128,.04);
		border: 1px solid rgba(128,128,128,.1); border-radius: 4px; padding: 8px 10px; min-height: 60px; }
	.dgsoc-box-title { font-size: 10px; font-weight: 700; margin-bottom: 6px; }
	.dgsoc-alert-item { display: flex; gap: 6px; padding: 4px 0;
		border-bottom: 1px solid rgba(128,128,128,.07); align-items: flex-start; }
	.dgsoc-alert-item:last-child { border-bottom: none; }
	.dgsoc-alert-dot { width: 5px; height: 5px; border-radius: 50%; flex-shrink: 0; margin-top: 3px; }
	.dgsoc-alert-type { font-size: 10px; font-weight: 500; }
	.dgsoc-alert-meta { font-size: 9px; color: #999; margin-top: 1px; }
	.dgsoc-alert-time { font-size: 9px; font-family: monospace; color: #999; margin-left: auto; flex-shrink: 0; }
	.dgsoc-host-item { display: flex; align-items: center; gap: 6px;
		padding: 3px 0; border-bottom: 1px solid rgba(128,128,128,.07); font-size: 10px; }
	.dgsoc-host-item:last-child { border-bottom: none; }
	.dgsoc-host-dot { width: 5px; height: 5px; border-radius: 50%; flex-shrink: 0; }
	.dgsoc-host-name { flex: 1; font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.dgsoc-host-status { font-size: 9px; color: #999; }
');

// KPIs
$kpi_div = (new CDiv())->addClass('dgsoc-kpis');
foreach ([
	['Eventos 24h', $kpis['events'],  $kpis['ips'].' IPs distintos',  '#d63939'],
	['Tentativas',  number_format((int)$kpis['attempts'],0,',','.'), 'ultimas 24h', '#f0a30a'],
	['Bloqueados',  number_format((int)$kpis['blocks'],0,',','.'),   $kpis['rate'].'% taxa', '#2fa84f'],
	['Criticos',    $kpis['critical'], 'score >= 7',                  '#9b59b6'],
] as [$lbl, $val, $sub, $color]) {
	$kpi_div->addItem(
		(new CDiv())
			->addClass('dgsoc-kpi')
			->addStyle("border-top-color:$color")
			->addItem((new CDiv($lbl))->addClass('dgsoc-kpi-label'))
			->addItem((new CDiv($val))->addClass('dgsoc-kpi-value')->addStyle("color:$color"))
			->addItem((new CDiv($sub))->addClass('dgsoc-kpi-sub'))
	);
}

// Timeline
$tl_track = (new CDiv())->addClass('dgsoc-tl-track');
foreach ([
	['done','v','Anomalia', 'T+0s', '#2fa84f'],
	['done','v','Threshold','T+30s','#2fa84f'],
	['done','v','Trigger',  'T+32s','#2fa84f'],
	['done','!','Alerta',   'T+45s','#d63939'],
	['done','v','NOC AI',   'T+2m', '#2fa84f'],
	['act', '>','Mitigacao','T+8m', '#f0a30a'],
] as [$cls, $icon, $name, $time, $color]) {
	$tl_track->addItem(
		(new CDiv())
			->addClass("dgsoc-tl-step $cls")
			->addItem((new CDiv($icon))->addClass('dgsoc-tl-circle'))
			->addItem((new CDiv($name))->addClass('dgsoc-tl-name'))
			->addItem((new CDiv($time))->addClass('dgsoc-tl-time')->addStyle("color:$color"))
	);
}
$tl_metrics = (new CDiv())->addClass('dgsoc-tl-metrics');
foreach ([['45s','#2fa84f','Anomalia->Alerta'],['8m','#f0a30a','->Mitigacao'],['1.57G','#d63939','Pico']] as [$v,$c,$l]) {
	$tl_metrics->addItem(
		(new CDiv())
			->addClass('dgsoc-tl-m')
			->addItem((new CDiv($v))->addClass('dgsoc-tl-mv')->addStyle("color:$c"))
			->addItem((new CDiv($l))->addClass('dgsoc-tl-mk'))
	);
}
$timeline = (new CDiv())
	->addClass('dgsoc-tl')
	->addItem((new CDiv('Tempo de resposta ao incidente'))->addClass('dgsoc-tl-title'))
	->addItem($tl_track)
	->addItem($tl_metrics);

// Alertas
$alerts_box = (new CDiv())->addClass('dgsoc-alerts')
	->addItem((new CDiv(_('Alertas recentes')))->addClass('dgsoc-box-title'));
if ($alerts) {
	foreach (array_slice($alerts, 0, 4) as $a) {
		$color = $sc[$a['severity_label'] ?? 'info'] ?? '#999';
		$alerts_box->addItem(
			(new CDiv())
				->addClass('dgsoc-alert-item')
				->addItem((new CDiv())->addClass('dgsoc-alert-dot')->addStyle("background:$color"))
				->addItem(
					(new CDiv())
						->addStyle('flex:1;min-width:0')
						->addItem((new CDiv(htmlspecialchars(str_replace('_',' ',$a['attack_type']??''))))->addClass('dgsoc-alert-type'))
						->addItem((new CDiv(htmlspecialchars($a['src_ip']??'').' - '.htmlspecialchars($a['host']??'')))->addClass('dgsoc-alert-meta'))
				)
				->addItem((new CDiv(date('H:i',strtotime($a['last_seen']??'now'))))->addClass('dgsoc-alert-time'))
		);
	}
} else {
	$alerts_box->addItem((new CDiv(_('Nenhum alerta recente')))->addStyle('color:#999;font-size:10px;padding:6px 0'));
}

// Hosts
$hosts_box = (new CDiv())->addClass('dgsoc-hosts')
	->addItem((new CDiv(_('Hosts').' ('.count($hosts).')'))->addClass('dgsoc-box-title'));
if ($hosts) {
	foreach (array_slice($hosts, 0, 5) as $h) {
		$online = (int)($h['status']??1)===0 && ($h['heartbeat']??0)>0;
		$hosts_box->addItem(
			(new CDiv())
				->addClass('dgsoc-host-item')
				->addItem((new CDiv())->addClass('dgsoc-host-dot')->addStyle('background:'.($online?'#2fa84f':'#d63939')))
				->addItem((new CDiv(htmlspecialchars($h['host']??'')))->addClass('dgsoc-host-name'))
				->addItem((new CDiv($online?'OK':'Off'))->addClass('dgsoc-host-status'))
		);
	}
} else {
	$hosts_box->addItem((new CDiv(_('Nenhum host encontrado')))->addStyle('color:#999;font-size:10px'));
}

(new CWidgetView($data))
	->addItem($style)
	->addItem($kpi_div)
	->addItem($timeline)
	->addItem((new CDiv())->addClass('dgsoc-bottom')->addItem($alerts_box)->addItem($hosts_box))
	->show();
