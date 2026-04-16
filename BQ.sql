-- Step 1: Filter your metadata and embeddings into a small temp table
CREATE OR REPLACE TEMP TABLE filtered_brand_data AS
SELECT 
  e.skid, 
  e.embedding, 
  m.`Product Name`
FROM `maven-search-493109.slikk_data.slikk_vector_embeddings` AS e
JOIN `maven-search-493109.slikk_data.slikk_balanced_15k` AS m 
  ON e.skid = m.skid
WHERE m.`Brand Name` = 'Desired Brand';

-- Step 2: Run the vector search on that small temp table
SELECT
  base.skid,
  base.`Product Name`,
  distance
FROM
  VECTOR_SEARCH(
    (SELECT * FROM filtered_brand_data), -- Simple SELECT only
    'embedding',
    (SELECT [0.12, 0.05, ...] AS query_vector), 
    top_k => 10,
    distance_type => 'COSINE'
  );
