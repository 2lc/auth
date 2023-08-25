 SELECT ltrim(to_char(t.id, '000000'::text)) AS id,
    t.grupo_atendimento AS grupo,
    COALESCE(( SELECT users.name
           FROM users
          WHERE users.id = t.user_abertura), 'Admin'::text) AS usuario,
        CASE t.status
            WHEN 0 THEN 'Aguardando Atendimento'::text
            WHEN 1 THEN 'Em Atendimento'::text
            WHEN 2 THEN 'Aguardando Usuário'::text
            WHEN 3 THEN 'Fechado'::text
            ELSE 'Other'::text
        END AS status,
    to_char((t.created_at AT TIME ZONE 'Brazil/East'::text), 'DD/MM/YYYY HH24:MI:SS'::text) AS data,
    t.ocorrencia
   FROM tickets t
  ORDER BY t.id;