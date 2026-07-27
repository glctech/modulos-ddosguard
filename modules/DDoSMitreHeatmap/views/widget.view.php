<?php declare(strict_types = 0);
/**
 * DDoS Guard - MITRE ATT&CK Heatmap - view
 * @var CView $this
 * @var array $data
 */
$tactics = $data['tactics'];
$max = max(1, max(array_column($tactics, 'count')));

$style = (new CTag('style', true))->addItem('
	.dgmitre { display: flex; flex-direction: column; gap: 6px; height: 100%; }
	.dgmitre-title { font-size: 10px; font-weight: 700; }
	.dgmitre-grid { display: grid; grid-template-columns: repeat(3,1fr); gap: 5px; flex: 1; }
	.dgmitre-cell { border-radius: 4px; padding: 8px 10px;
		display: flex; flex-direction: column; gap: 2px;
		border: 1px solid rgba(128,128,128,.12); }
	.dgmitre-tactic { font-size: 8px; text-transform: uppercase; letter-spacing: .06em; font-weight: 600; }
	.dgmitre-count { font-size: 22px; font-weight: 700; line-height: 1; font-family: monospace; }
	.dgmitre-tech { font-size: 9px; font-family: monospace; }
	.dgmitre-bar { height: 3px; border-radius: 2px; margin-top: 3px; background: rgba(128,128,128,.15); }
	.dgmitre-fill { height: 100%; border-radius: 2px; }
');

$grid = (new CDiv())->addClass('dgmitre-grid');
foreach ($tactics as $t) {
	$pct   = $max > 0 ? round($t['count'] / $max * 100) : 0;
	$bg    = $t['color'];
	$alpha = $t['count'] > 0 ? '18' : '0a';
	$grid->addItem(
		(new CDiv())
			->addClass('dgmitre-cell')
			->addStyle("background:{$bg}{$alpha};border-color:{$bg}44")
			->addItem((new CDiv(htmlspecialchars($t['tactic'])))->addClass('dgmitre-tactic')->addStyle("color:$bg"))
			->addItem((new CDiv($t['count']))->addClass('dgmitre-count')->addStyle('color:'.($t['count']>0?$bg:'#999')))
			->addItem((new CDiv(htmlspecialchars($t['tech'])))->addClass('dgmitre-tech')->addStyle("color:{$bg}aa"))
			->addItem(
				(new CDiv())->addClass('dgmitre-bar')
					->addItem((new CDiv())->addClass('dgmitre-fill')->addStyle("width:{$pct}%;background:{$bg}"))
			)
	);
}

(new CWidgetView($data))
	->addItem($style)
	->addItem(
		(new CDiv())
			->addClass('dgmitre')
			->addItem((new CDiv(_('MITRE ATT&CK - Tacticas detectadas (24h)')))->addClass('dgmitre-title'))
			->addItem($grid)
	)
	->show();
