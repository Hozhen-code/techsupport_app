-- revisions 클린업
DELETE FROM manual_node_revisions;

-- 새로 추가된 노드 모두에 대해 revision 생성
INSERT INTO manual_node_revisions (node_id, software_id, version_id, checked)
SELECT id, 2, 1, 0 FROM manual_nodes;
