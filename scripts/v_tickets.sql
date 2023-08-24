CREATE OR REPLACE VIEW v_tickets AS 
Select to_char(t.id,'000000') as Id,
t.grupo_atendimento as Grupo,
CASE t.status WHEN 0 THEN 'Aguardando Atendimento'
              WHEN 1 THEN 'Em Atendimento'
			  WHEN 2 THEN 'Aguardando Usuário'
			  WHEN 3 THEN 'Fechado'
              ELSE 'Other'
       END
as Status,
to_char(t.created_at AT TIME ZONE 'Brazil/East','DD/MM/YYYY HH24:MI:SS') as Data,
t.ocorrencia as Ocorrencia 
from tickets t Order by t.id