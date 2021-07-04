#!/usr/local/bin/php -q
<?php
  define('MAX_ALLOWED_INFECTED_FILES', 1000); 
    
  stream_set_blocking(STDIN, 0);
  $stdin = fopen('php://stdin', 'r');
  $data = stream_get_contents($stdin);
  $json = json_decode(trim($data), true);
    
  switch ($json['event']) {
    case 'malware-detected':
    // if it's infection?
       if ($json['subtype'] == 'critical') {
       // retrieve the scanning report
       $report = json_decode(file_get_contents($json['params']['tmp_filename']), true);
       $by_users = array();
    
       // combine infected files by users
       foreach ($report as $entry) {
         if (!isset($by_users[$entry['username']])) {
           $by_users[$entry['username']] = array();
         }
         $by_users[$entry['username']][] = $entry['file'];
       }
    
       // suspend all accounts, where number of infected files more than MAX_ALLOWED_INFECTED_FILES
       foreach ($by_users as $user => $files) {
         if (count($files) > MAX_ALLOWED_INFECTED_FILES) {
           exec('/scripts/suspendacct ' . $user . ' "Account has (count($files) malicious files" 1');
           exec('/usr/bin/curl' -i -X POST -H 'Content-Type: application/json' -d '{"text": " :warning: $user has been suspended - (count($files) malicious files "}' https://{your-webhook-url/}
         }
       }
    }
    break;
}
