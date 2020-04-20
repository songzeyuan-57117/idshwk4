event zeek_init()
    {
    local r1 = SumStats::Reducer($stream="all_code_num", $apply=set(SumStats::UNIQUE));
    local r2 = SumStats::Reducer($stream="all_404_num", $apply=set(SumStats::UNIQUE));
    local r3 = SumStats::Reducer($stream="all_404_url_num", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="scan_capture",
                      $epoch=10min,
                      $reducers=set(r1,r2,r3),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        	local r11 = result["all_code_num"];
                        	local r22 = result["all_404_num"];
	        		local r33 = result["all_404_url_num"];
	        		if(r22$num>2&&(r22$num/r11$num)>0.2)
	        		{
	        			if((r33$unique/r22$num)>0.5)
	        			{
	        				print fmt("%s is a scanner with %d scan attemps on %d urls", 
                        			key$host, r22$num, r33$unique);
                        		}
	        		}
                        }]);
    }

event http_reply(c: connection, version: string, code: count, reason: string)
    {
    	SumStats::observe("all_code_num", [$host=c$id$orig_h], [$num=code]);
	if(code==404)
	{
		SumStats::observe("all_404_num", [$host=c$id$orig_h], [$num=code]);
		SumStats::observe("all_404_url_num", [$host=c$id$orig_h], [$str=c$http$uri]);
	}
    }
