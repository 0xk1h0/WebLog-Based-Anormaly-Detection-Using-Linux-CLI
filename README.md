# WebLog-Based-Anormaly-Detection Using Linux CLI
웹로그 기반 정보유출징후 탐지
Linux(Ubuntu 20.04) CLI를 활용한 Weblog Analysis

### 데이터 살펴보기
* 정보유출 징후가 식별되는 데이터로, 전처리로 Datetime / SIP / Method / Payload / Version / ResponseCode / ResponseByte로 칼럼 추출하였습니다.
* 칼럼 추출 간 tshark를 활용하였고 CLI에서 전처리를 하다보니 다양한 ServerSet에서 활용하기에 편리하다는 장점이 있습니다.
![image](https://user-images.githubusercontent.com/47383452/141668694-5991c6e0-7566-4828-a291-abfcffff3e0b.png)
* 약 154MB의 전처리된 데이터이며, 6000만 Line의 세선데이터가 포함되어 있습니다.

### 1. Connection based Analysis
* 일자별로 연결기반 분석을 해보면,
![image](https://user-images.githubusercontent.com/47383452/141672002-7acd0782-50b1-4da8-b6be-506b44f55c1d.png)
* 특정 일자에서 상대적으로 많은 Session이 발생한 것을 확인할 수 있습니다.
` cat srv1_access_daily.tsv | feedgnuplot --domain --timefmt "%Y-%m-%d" --with "boxes lt -1" --legend 0 "daily HTTP Session"`

##### SIP 접속 수
![image](https://user-images.githubusercontent.com/47383452/141672273-7fddfc6b-9c45-4e5f-9ef0-437679151439.png)

일자별 IP 반복수(재방문) 확인

![image](https://user-images.githubusercontent.com/47383452/141672287-d6a13606-2c26-44a2-9ed2-a974a88a8d07.png)

![image](https://user-images.githubusercontent.com/47383452/141672674-3cb289d2-6fb3-4851-81da-1441f5cfad89.png)

![image](https://user-images.githubusercontent.com/47383452/141672741-1270a547-21c6-4872-bc84-44a46381944b.png)
* 일자별 SESSION, SIPCNT, SESS/SIPCNT를 시각화하였고 노이즈 제거가 필요한 것으로 확인했습니다.

![image](https://user-images.githubusercontent.com/47383452/141672840-f86d0f38-ac9a-4db7-b752-2ab8238d5ca0.png)
* Boxplot

* SIP COUNT > 100 인 일자 중, 상위 SEESSION / SIPCOUNT의 수를 보면 다음과 같습니다.
![image](https://user-images.githubusercontent.com/47383452/142240852-a9db5f73-7fab-424a-b7e0-b29f58967bfe.png)

` cat sess_ovr_sipcnt.tsv | awk '$3 > 100{print $0}' | awk '{print $1 "\t" $4}' | feedgnuplot --domain --timefmt '%Y-%m-%d' --lines --points --legend 0 "SESS/SIPCNT"`
 ![image](https://user-images.githubusercontent.com/47383452/142242977-e84a1b2b-18b1-4aba-9747-dd95674d89ec.png)
* 특정 구간에서 유난히 높은 수치를 보이는 것이 보입니다. 400 이상인 일자를 구분하여 DDoS 여부파악이 필요할 것 같습니다.
* SESS.CIPCNT > 400 인 일자를 ddos_event.tsv로 생성
 ```
 for d in $(cat ddos_event.tsv | awk '{print $1}')
 do
 zcat ../srv1_accesslog.gz | awk '$1==date{print $0}' date=$d > $DATE"_ddos_evt.tsv"
 done
 ```
![image](https://user-images.githubusercontent.com/47383452/142251515-550f6cdb-9d13-4a1c-97c4-3462a1057988.png)

패킷 레벨로 접근하면 누가 자원을 제일 많이 소모했는가 / 가장 수치가 높은 2017-07-03을 한번 확인해보겠습니다.
- ` zcat 2017-07-03_ddos_evt.tsv.gz | awk '{print $2}' | sort | uniq -c | awk '{print $2 "\t" $1}' | feedgnuplot --domain --timefmt "%H:%M:%S" --with 'boxes lt -1' --legend 0 "2017-07-03 sps"`
 ![image](https://user-images.githubusercontent.com/47383452/142252794-944c0a6c-fa02-4091-9331-896017b5ea25.png)
- ` zcat 2017-07-03_ddos_evt.tsv.gz | awk '{print $2 "\t" $3}' | sort -u | awk '{print $1}' | sort | uniq -c | awk '{print $2 "\t" $1}' > 2017-07-03.sipsec.tsv`
- ` cat 2017-07-03.sipsec.tsv | feedgnuplot --domain --timefmt "%H:%M:%S" --with 'boxes lt 3' --legend 0 "SIP per Second"`
  - SIP PER SECOND
 ![image](https://user-images.githubusercontent.com/47383452/142253954-1dcb617d-053d-4b0c-a6b8-bdf2834e407a.png)
 

- ` cat spm.tsv | feedgnuplot --domain --timefmt "%H:%M" --lines --points --legend 0 "SESSION PER MINUTE"`
  - SESSION PER MINUTE
 ![image](https://user-images.githubusercontent.com/47383452/142255708-0a1694c6-43e3-4283-9cd9-45a624e62672.png)
 
 ```
   for m in $(cat min)
   do
   TS=$m
   SPM=$(cat spm.tsv | awk '$1==min{print $2}' min=$m)
   SIP=$(cat sipmain.tsv | awk '$1==min{print $2}' min=$m)
   echo $TS $SPM $SIP
   done | awk '{print $0 "\t" ($2+1)/($3+1)}' > ddos_min.tsv
```
- ` cat ddos_min.tsv  | feedgnuplot --domain --timefmt "%H:%M" --lines --points --y2 2 --legend 0 "Session per Minute" --legend 1 "Nr. of SIP per Minute" --legend 2 "SPM / SIPMIN"`
 ![image](https://user-images.githubusercontent.com/47383452/142257473-7b9c7ae5-e6d9-421b-b345-3bca484add68.png)
  - 2017-07-03 15:00 ~ 19:00 / 20:30 ~ 21:00
 
* 재방문에 의한 공격 IP 확인
   ```
   cat ts_min_sip | awk '{print $2}' | sort | uniq -c | while read line
   do
   IP=$(echo $line | awk '{print $2}')
   FN=$(echo $line | awk '{print $1 ".revisit"}')
   echo $IP >> $FN
   done
   ```
   ![image](https://user-images.githubusercontent.com/47383452/142261157-7d8275bc-34d3-48f1-8c67-701e82368c6f.png)
   
   ```
   zcat 2017-07-03_ddos_evt.tsv.gz | awk '{print $3}' | sort | uniq -c | sort -rn | head
   200465 IP0041058
   118835 IP0040986
    70076 IP0001113
    68682 IP0040922
    29853 IP0084544
    22450 IP1062364
    18371 IP0000782
    17692 IP0001719
    11529 IP0173656
     7691 IP0001227
   ```
   * IP0041058
   ![image](https://user-images.githubusercontent.com/47383452/142262931-3aeeec52-d08d-43c8-83f6-dda7d9f30473.png)
   * IP0040986
   ![image](https://user-images.githubusercontent.com/47383452/142263134-619abc5e-451f-4ca1-b7f8-de6b8b88c802.png)
   * IP0001113
   ![image](https://user-images.githubusercontent.com/47383452/142263268-c65bc249-48f0-42de-aeec-1bba10263fde.png)
   * IP0040922
   ![image](https://user-images.githubusercontent.com/47383452/142263473-11b65b5c-75b1-4a99-83c0-4fab9f6df664.png)
   
   #### DDoS 공격 / 특정 시간대에 집중적으로 트래픽이 발생하는 IP를 발견할 수 있었습니다. Revisit 비율이 높고 패킷레벨에서 많은 자원을 소비한 것을 확인하였습니다.

### 2. Response Code Based Analysis

##### 응답코드 400~ 추출

```
zcat srv1_accesslog.gz | awk '$7~/^[12345]/{print $1 "\t" $7}'|sort | uniq -c | awk '{print $2 "\t" $3 "\t" $1}' | 
awk '{if ($2 >= "400" && $2 < 500) print ($0)} > 400_rcode.tsv
```
```
cat 400_rcode.tsv | sort -rnk 3 | head | awk '{print $3}'|head
13851
13574
5228
3583
3166
3109
2976
2760
2698
2665
```
* 응답코드 4XX인 레코드 시각화
 ```
 cat 400_r_code.tsv | sort -rnk 3 | awk ‘{print $3}’ | feedgnuplot –histogram 0 –ymax 5
 ```
![image](https://user-images.githubusercontent.com/47383452/142265566-814b9174-acda-48f3-882b-74e1ec627a38.png)
```
cat 400_rcode.tsv | sort -rnk 3 | awk '{print $1 "\t" $3}' | feedgnuplot --domain --timefmt '%Y-%m-%d' --points
```
![image](https://user-images.githubusercontent.com/47383452/142265627-e720ffc2-ca86-4874-acda-871dfa11d92e.png)

* 응답코드 4XX인 SIP
```
zcat srv1_accesslog.gz | awk '$7~/^[12345]/{print $3 "\t" $7}'|sort | uniq -c | awk '{print $2 "\t" $3 "\t" $1}' | awk '{if ($2 >=400 && $2 < 500) print $0}' > sip_rcode.tsv
```
![image](https://user-images.githubusercontent.com/47383452/142265796-82e872a3-abcf-42e9-9958-cd9834112a23.png)

```
cat sip_rcode.tsv | sort -rnk 3 | head
IP1093735	404	17010
IP0053005	404	11867
IP0008180	404	11730
IP0013767	404	11297
IP0099074	404	10495
IP0002194	404	10088
IP1056836	404	10049
IP1086971	404	9032
IP1087023	404	7962
IP1056822	404	6520
```

* 4XX가 상위 100개인 IP 통신 추출
```
cat sip_rcode.tsv | sort -rnk 3 | head -100 > top_sip.ip
```
```
for ip in $(cat top_sip.ip)
> do
> zcat srv1_accesslog.gz | awk '$3==sip{print $0}' sip=$ip > $ip".log"
> done
```
![image](https://user-images.githubusercontent.com/47383452/142265986-cdba40db-b08b-4920-a443-3adc10a6f699.png)
```
cat IP* | awk '$7!=""{print $1 "\t" $7}' | awk '{if (($2 >= 200 && $2 < 300) || ($2 >= 400 && $2 < 500)) print $0}' > 2XX_4XX.log
cat 2XX_4XX.log |awk '{print $1 "\t" (int($2/200)-int($2/400)) "\t" int($2/400)}' | awk '$1==prv{r2+=$2;r4+=$3;next}{print prv "\t" r2 "\t" r4; prv=$1;r2=$2; r4=$3}' |
feedgnuplot --domain --points  --timefmt "%Y-%m-%d" --title "2xx AND 4xx Response Frequency" --legend 0 "2XX" --legend 1 "4XX"
```
![image](https://user-images.githubusercontent.com/47383452/142266167-57ee1443-425b-4df1-9526-67ca7c9b3049.png)

```
cat IP* | awk '$7!=""{print $1 "\t" $3 "\t" $7}' |sort| awk '{print $1 "_" $2 "_" int($3/100)*100}' | uniq -c | sort -rn | head -20
```
![image](https://user-images.githubusercontent.com/47383452/142266234-73b5651e-0a3c-4955-adfd-db186669e42c.png)

##### IP0008180과 IP0053005의 400번대 응답코드가 타 IP대비 높은 것을 확인 할 수 있다. 

* IP0053005
```
cat IP0053005.log | awk '$7!=""{print $1 "\t" $7}' | sort | awk '{print $1 "\t" int(($2)/100)*100}' |
awk '{print $1 "\t" int($2/200)-int($2/400) "\t" int($2/300) "\t" int($2/400) "\t" int($2/500)}'|
awk '$1==prv{r2+=$2;r3+=$3;r4+=$4;r5+=$5;next}{print prv "\t" r2 "\t" r3 "\t" r4 "\t" r5; prv=$1;r2=$2;r3=$3; r4=$4;r5=$5}'
```

```
		 	200	300 400	500
2017-07-04	58	3	3	0
2017-08-01	13664	11944	11837	4
2017-09-21	63	4	4	0
2017-10-10	44	2	2	0
2017-10-11	318	21	20	1
2017-10-13	3	2	2	0
2017-10-20	36	8	3	0
2018-01-03	80	2	1	0
```
* IP0008180
```
cat IP0008180.log | awk '$7!=""{print $1 "\t" $7}' | sort | awk '{print $1 "\t" int(($2)/100)*100}' |
awk '{print $1 "\t" int($2/200)-int($2/400) "\t" int($2/300) "\t" int($2/400) "\t" int($2/500)}'|
awk '$1==prv{r2+=$2;r3+=$3;r4+=$4;r5+=$5;next}{print prv "\t" r2 "\t" r3 "\t" r4 "\t" r5; prv=$1;r2=$2;r3=$3; r4=$4;r5=$5}'
```
```
			200	300	400	500	
2017-03-13	270	74	28	0
2017-03-14	12688	11837	11680	6
```

