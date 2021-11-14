# WebLog-Based-Anormaly-Detection / NOT ML (
웹로그 기반 정보유출징후 탐지 내용입니다.[KISA 웹로그 분석 고급과정]
Linux(Ubuntu 20.04) CLI를 활용한 Weblog Analysis 과정입니다.

보안서약으로 인해 데이터는 배포 못하는 점 너그러이 양해를 부탁드림니다. :/

### 데이터 살펴보기
* 정보유출 징후가 식별되는 데이터로, 전처리로 Datetime / SIP / Method / Payload / Version / ResponseCode / ResponseByte로 칼럼 추출하였습니다.
* 칼럼 추출 간 tshark를 활용하였고 CLI에서 전처리를 하다보니 다양한 ServerSet에서 활용하기에 편리하다는 장점이 있습니다.
![image](https://user-images.githubusercontent.com/47383452/141668694-5991c6e0-7566-4828-a291-abfcffff3e0b.png)
* 약 154MB의 전처리된 데이터이며, 6000만 Line의 세선데이터가 포함되어 있습니다.

### Connection based Analysis
* 일자별로 연결기반 분석을 해보면,
![image](https://user-images.githubusercontent.com/47383452/141672002-7acd0782-50b1-4da8-b6be-506b44f55c1d.png)
* 특정 일자에서 상대적으로 많은 Session이 발생한 것을 확인할 수 있습니다.
* cat srv1_access_daily.tsv | feedgnuplot --domain --timefmt "%Y-%m-%d" --with "boxes lt -1" --legend 0 "daily HTTP Session"

##### SIP 접속 수
![image](https://user-images.githubusercontent.com/47383452/141672273-7fddfc6b-9c45-4e5f-9ef0-437679151439.png)

일자별 IP 반복수(재방문) 확인

![image](https://user-images.githubusercontent.com/47383452/141672287-d6a13606-2c26-44a2-9ed2-a974a88a8d07.png)

![image](https://user-images.githubusercontent.com/47383452/141672674-3cb289d2-6fb3-4851-81da-1441f5cfad89.png)

![image](https://user-images.githubusercontent.com/47383452/141672741-1270a547-21c6-4872-bc84-44a46381944b.png)
* 일자별 SESSION, SIPCNT, SESS/SIPCNT를 시각화하였고 노이즈 제거가 필요한 것으로 확인했습니다.

![image](https://user-images.githubusercontent.com/47383452/141672840-f86d0f38-ac9a-4db7-b752-2ab8238d5ca0.png)

#
