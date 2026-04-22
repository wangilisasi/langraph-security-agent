# Default API-Led Architecture Sequence Diagram

```text
Participants:
  C  = Client
  A  = FastAPI /analyze
  D  = Detector
  R  = Response Nodes
  DB = SQLite
  B  = Background Thread
  G  = LangGraph
  T  = Security Tools

1. C  -> A   : POST /analyze {method, url, headers, body, source_ip}
2. A  -> DB  : is_ip_banned(source_ip)?

If IP already banned:
3. DB -> A   : true
4. A  -> C   : attack / block

If IP not banned:
3. DB -> A   : false
4. A  -> D   : parse_http_request(...)
5. A  -> D   : predict(http_request)
6. D  -> A   : confidence

If confidence >= HIGH_THRESHOLD:
7.  A  -> R  : auto_respond(state)
8.  R  -> DB : update_ip_after_request(is_attack=True)
9.  R  -> DB : set_ip_ban(source_ip, temp_ban)        [repeat offender only]
10. R  -> DB : log_incident(...)
11. R  -> A  : response
12. A  -> C  : attack / block or temp_ban

If confidence <= LOW_THRESHOLD:
7.  A  -> R  : pass_through(state)
8.  R  -> DB : update_ip_after_request(is_attack=False)
9.  R  -> DB : log_incident(...)
10. R  -> A  : response
11. A  -> C  : benign / log_only

If request is in the grey zone:
7.  A  -> DB : update_ip_after_request(is_grey_zone=True)
8.  A  -> B  : queue_llm_analysis(http_request, detection_result)
9.  A  -> C  : pending / under_review

Background analysis:
10. B  -> G  : security_agent.invoke(...)
11. G  -> G  : prepare_llm_context
12. G  -> G  : security_chatbot

Tool-assisted reasoning loop:
13. G  -> T  : inspect_request_fields(...)
14. T  -> G  : request breakdown
15. G  -> T  : check_ip_history(source_ip)
16. T  -> DB : get_ip_reputation(), get_recent_incidents()
17. T  -> G  : IP history
18. G  -> T  : log_security_incident(...)
19. T  -> DB : update_ip_after_request(...)
20. T  -> DB : log_incident(...)
21. T  -> G  : logged
22. G  -> T  : block_ip(source_ip)                    [confirmed attack only]
23. T  -> DB : set_ip_ban(...)                        [confirmed attack only]
24. T  -> G  : banned                                [confirmed attack only]
25. G  -> T  : send_alert(...)                       [alert needed only]
26. T  -> G  : alert written                         [alert needed only]
```
